package binlog

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"reflect"
	"strings"
	"time"
)

// Misc. Constants
const NullByte byte = 0

var EOF = bytes.NewBuffer([]byte{NullByte})

const MaxPacketSize = MaxUint16

// MySQL Packet Data Types
const TypeNullTerminatedString = int(0)
const TypeFixedString = int(1)
const TypeFixedInt = int(2)
const TypeLenEncInt = int(3)
const TypeRestOfPacketString = int(4)
const TypeLenEncString = int(5)

// Integer Maximums
const MaxUint08 = 1<<8 - 1
const MaxUint16 = 1<<16 - 1
const MaxUint24 = 1<<24 - 1
const MaxUint64 = 1<<64 - 1

// Packet Statuses
const StatusOK = 0x00
const StatusEOF = 0xFE
const StatusErr = 0xFF
const StatusAuth = 0x01

type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Pass       string `json:"password"`
	Database   string `json:"database"`
	SSL        bool   `json:"ssl"`
	SSLCA      string `json:"ssl-ca"`
	SSLCer     string `json:"ssl-cer"`
	SSLKey     string `json:"ssl-key"`
	VerifyCert bool   `json:"verify-cert"`
	ServerId   uint64 `json:"server-id"`
	BinLogFile string `json:"binlog-file"`
	Timeout    time.Duration
}

func newBinlogConfig(dsn string) (*Config, error) {
	var err error

	b, err := ioutil.ReadFile(dsn)
	if err != nil {
		return nil, err
	}

	config := Config{}
	err = json.Unmarshal(b, &config)

	return &config, err
}

type Conn struct {
	Config            *Config
	curConn           net.Conn
	tcpConn           *net.TCPConn
	secTCPConn        *tls.Conn
	Handshake         *Handshake
	HandshakeResponse *HandshakeResponse
	buffer            *bufio.ReadWriter
	scanner           *bufio.Scanner
	err               error
	sequenceId        uint64
	writeBuf          *bytes.Buffer
	StausFlags        *StatusFlags
	Listener          *net.Listener
}

func newBinlogConn(config *Config) Conn {
	return Conn{
		Config:     config,
		sequenceId: 1,
	}
}

func (c Conn) Prepare(query string) (driver.Stmt, error) {
	return nil, nil
}

func (c Conn) Close() error {
	return nil
}

func (c Conn) Begin() (driver.Tx, error) {
	return nil, nil
}

type Driver struct{}

func (d Driver) Open(dsn string) (driver.Conn, error) {
	config, err := newBinlogConfig(dsn)
	if nil != err {
		return nil, err
	}

	c := newBinlogConn(config)

	var t interface{}
	dialer := net.Dialer{Timeout: c.Config.Timeout}
	addr := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)
	t, err = dialer.Dial("tcp", addr)

	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && !netErr.Temporary() {
			fmt.Printf("Error: %s", netErr.Error())
			return nil, err
		}
	} else {
		c.tcpConn = t.(*net.TCPConn)
		c.setConnection(t.(net.Conn))
	}

	err = c.decodeHandshakePacket()
	if err != nil {
		return nil, err
	}

	c.HandshakeResponse = c.NewHandshakeResponse()

	// If we are on SSL send SSL_Request packet now
	if c.Config.SSL {
		err = c.writeSSLRequestPacket()
		if err != nil {
			return nil, err
		}

		tlsConf := NewClientTLSConfig(
			c.Config.SSLKey,
			c.Config.SSLCer,
			[]byte(c.Config.SSLCA),
			c.Config.VerifyCert,
			c.Config.Host,
		)

		c.secTCPConn = tls.Client(c.tcpConn, tlsConf)
		c.setConnection(c.secTCPConn)
	}

	err = c.writeHandshakeResponse()
	if err != nil {
		return nil, err
	}

	// Listen for auth response.
	_, err = c.listen()
	if err != nil {
		// Auth failed.
		return nil, err
	}

	// Auth completed successfully, move to command phase.
	c.sequenceId = 0

	// Start binlog stream
	err = c.startBinLogStream()
	if err != nil {
		return nil, err
	}

	err = c.listenForBinlog()
	if err != nil {
		return nil, err
	}

	return c, err
}

func (c *Conn) listen() (interface{}, error) {
	ph, err := c.getPacketHeader()
	if err != nil {
		return nil, err
	}
	c.sequenceId++

	var res interface{}

	switch ph.Status {
	case StatusAuth:
		res, err := c.decodeAuthMoreDataResponsePacket(ph)
		if err != nil {
			return nil, err
		}

		switch res.Data {
		case SHA2_FAST_AUTH_SUCCESS:
		case SHA2_REQUEST_PUBLIC_KEY:
		case SHA2_PERFORM_FULL_AUTHENTICATION:
			c.putBytes(append([]byte(c.Config.Pass), NullByte))
			if c.Flush() != nil {
				return nil, c.Flush()
			}
		}

	case StatusEOF:
		fallthrough
	case StatusOK:
		res, err = c.decodeOKPacket(ph)
		if err != nil {
			return nil, err
		}
	case StatusErr:
		res, err = c.decodeErrorPacket(ph)
		if err != nil {
			return nil, err
		}

		err = errors.New(
			fmt.Sprintf(
				"Error %d: %s",
				res.(*ErrorPacket).ErrorCode,
				res.(*ErrorPacket).ErrorMessage,
			))

		return res, err
	}

	err = c.scanner.Err()
	if err != nil {
		return nil, err
	}

	return res, nil
}

type PacketHeader struct {
	Length     uint64
	SequenceID uint64
	Status     uint64
}

func (c *Conn) getPacketHeader() (PacketHeader, error) {
	ph := PacketHeader{}
	ph.Length = c.getInt(TypeFixedInt, 3)
	ph.SequenceID = c.getInt(TypeFixedInt, 1)
	ph.Status = c.getInt(TypeFixedInt, 1)

	err := c.scanner.Err()
	if err != nil {
		return ph, err
	}

	return ph, nil
}

func init() {
	sql.Register("mysql-binlog", &Driver{})
}

func (c *Conn) readBytes(l uint64) *bytes.Buffer {
	b := make([]byte, 0)
	for i := uint64(0); i < l; i++ {
		didScan := c.scanner.Scan()
		if !didScan {
			err := c.scanner.Err()
			if err == nil { // scanner reached EOF
				return EOF
			} else {
				panic(err) // @TODO Handle this gracefully.
			}

			return nil
		}

		b = append(b, c.scanner.Bytes()...)
	}

	return bytes.NewBuffer(b)
}

func (c *Conn) getBytesUntilEOF() *bytes.Buffer {
	l := uint64(1)
	s := c.readBytes(l)
	b := s.Bytes()

	for true {
		if uint64(s.Len()) != l || s.Bytes()[0] == NullByte {
			break
		}

		s := c.readBytes(uint64(l))
		if s == EOF || s == nil {
			return bytes.NewBuffer(b)
		}

		b = append(b, s.Bytes()...)
	}

	return bytes.NewBuffer(b)
}

func (c *Conn) getBytesUntilNull() *bytes.Buffer {
	l := uint64(1)
	s := c.readBytes(l)
	b := s.Bytes()

	for true {
		if uint64(s.Len()) != l || s.Bytes()[0] == NullByte {
			break
		}

		s = c.readBytes(uint64(l))
		b = append(b, s.Bytes()...)
	}

	return bytes.NewBuffer(b)
}

func (c *Conn) discardBytes(l uint64) {
	c.readBytes(l)
}

func (c *Conn) getInt(t int, l uint64) uint64 {
	var v uint64

	switch t {
	case TypeFixedInt:
		v = c.decFixedInt(l)
	case TypeLenEncInt:
		v = c.decLenEncInt()
	default:
		v = 0
	}

	return v
}

func (c *Conn) getString(t int, l uint64) string {
	var v string

	switch t {
	case TypeFixedString:
		v = c.decFixedString(l)
	case TypeLenEncString:
		v = string(c.decLenEncInt())
	case TypeNullTerminatedString:
		v = c.decNullTerminatedString()
	case TypeRestOfPacketString:
		v = c.decRestOfPacketString()
	default:
		v = ""
	}

	return v
}

func (c *Conn) decRestOfPacketString() string {
	b := c.getBytesUntilEOF()
	return string(b.Bytes())
}

func (c *Conn) decNullTerminatedString() string {
	b := c.getBytesUntilNull()
	return strings.TrimRight(b.String(), string(NullByte))
}

func (c *Conn) decFixedString(l uint64) string {
	b := c.readBytes(l)
	return b.String()
}

func (c *Conn) decLenEncInt() uint64 {
	var l uint16
	b := c.readBytes(1)
	br := bytes.NewReader(b.Bytes())
	_ = binary.Read(br, binary.LittleEndian, &l)
	if l > 0 {
		return c.decFixedInt(uint64(l))
	} else {
		return 0
	}
}

func (c *Conn) decFixedInt(l uint64) uint64 {
	var i uint64
	b := c.readBytes(l)

	if l <= 2 {
		var x uint16
		pb := c.padBytes(2, b.Bytes())
		br := bytes.NewReader(pb)
		_ = binary.Read(br, binary.LittleEndian, &x)
		i = uint64(x)
	} else if l <= 4 {
		var x uint32
		pb := c.padBytes(4, b.Bytes())
		br := bytes.NewReader(pb)
		_ = binary.Read(br, binary.LittleEndian, &x)
		i = uint64(x)
	} else if l <= 8 {
		var x uint64
		pb := c.padBytes(8, b.Bytes())
		br := bytes.NewReader(pb)
		_ = binary.Read(br, binary.LittleEndian, &x)
		i = x
	}

	return i
}

func (c *Conn) padBytes(l int, b []byte) []byte {
	bl := len(b)
	pl := l - bl
	for i := 0; i < pl; i++ {
		b = append(b, NullByte)
	}

	return b
}

func (c *Conn) encFixedLenInt(v uint64, l uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b[:l]
}

func (c *Conn) encLenEncInt(v uint64) []byte {
	prefix := make([]byte, 1)
	var b []byte
	switch {
	case v < MaxUint08:
		b = make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(v))
		b = b[:1]
	case v >= MaxUint08 && v < MaxUint16:
		prefix[0] = 0xFC
		b = make([]byte, 3)
		binary.LittleEndian.PutUint16(b, uint16(v))
		b = b[:2]
	case v >= MaxUint16 && v < MaxUint24:
		prefix[0] = 0xFD
		b = make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v))
		b = b[:3]
	case v >= MaxUint24 && v < MaxUint64:
		prefix[0] = 0xFE
		b = make([]byte, 9)
		binary.LittleEndian.PutUint64(b, uint64(v))
	}

	if len(b) > 1 {
		b = append(prefix, b...)
	}
	return b
}

func (c *Conn) bitmaskToStruct(b []byte, s interface{}) interface{} {
	l := len(b)
	t := reflect.TypeOf(s)
	v := reflect.New(t.Elem()).Elem()
	for i := uint(0); i < uint(v.NumField()); i++ {
		f := v.Field(int(i))
		var v bool
		switch {
		case l > 4:
			x := binary.LittleEndian.Uint64(b)
			flag := uint64(1 << i)
			v = x&flag > 0
		case l > 2:
			x := binary.LittleEndian.Uint32(b)
			flag := uint32(1 << i)
			v = x&flag > 0
		case l > 1:
			x := binary.LittleEndian.Uint16(b)
			flag := uint16(1 << i)
			v = x&flag > 0
		default:
			x := uint(b[0])
			flag := uint(1 << i)
			v = x&flag > 0
		}

		f.SetBool(v)
	}

	return v.Interface()
}

func (c *Conn) structToBitmask(s interface{}) []byte {
	t := reflect.TypeOf(s).Elem()
	sV := reflect.ValueOf(s).Elem()
	fC := uint(t.NumField())
	m := uint64(0)
	for i := uint(0); i < fC; i++ {
		f := sV.Field(int(i))
		v := f.Bool()
		if v {
			m |= 1 << i
		}
	}

	l := uint64(math.Ceil(float64(fC) / 8.0))
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, m)

	switch {
	case l > 4: // 64 bits
		b = b[:8]
	case l > 2: // 32 bits
		b = b[:4]
	case l > 1: // 16 bits
		b = b[:2]
	default: // 8 bits
		b = b[:1]
	}

	return b
}

func (c *Conn) putString(t int, v string) uint64 {
	b := make([]byte, 0)

	switch t {
	case TypeFixedString:
		b = c.encFixedString(v)
	case TypeNullTerminatedString:
		b = c.encNullTerminatedString(v)
	case TypeRestOfPacketString:
		b = c.encRestOfPacketString(v)
	}

	l, err := c.writeBuf.Write(b)
	if err != nil {
		c.err = err
	}

	return uint64(l)
}

func (c *Conn) encNullTerminatedString(v string) []byte {
	return append([]byte(v), NullByte)
}

func (c *Conn) encFixedString(v string) []byte {
	return []byte(v)
}

func (c *Conn) encRestOfPacketString(v string) []byte {
	s := c.encFixedString(v)
	return s
}

func (c *Conn) putInt(t int, v uint64, l uint64) uint64 {
	c.setupWriteBuffer()

	b := make([]byte, 0)

	switch t {
	case TypeFixedInt:
		b = c.encFixedLenInt(v, l)
	case TypeLenEncInt:
		b = c.encLenEncInt(v)
	}

	n, err := c.writeBuf.Write(b)
	if err != nil {
		c.err = err
	}

	return uint64(n)
}

func (c *Conn) putNullBytes(n uint64) uint64 {
	c.setupWriteBuffer()

	b := make([]byte, n)
	l, err := c.writeBuf.Write(b)
	if err != nil {
		c.err = err
	}

	return uint64(l)
}

func (c *Conn) putBytes(v []byte) uint64 {
	c.setupWriteBuffer()

	l, err := c.writeBuf.Write(v)
	if err != nil {
		c.err = err
	}

	return uint64(l)
}

func (c *Conn) Flush() error {
	if c.err != nil {
		return c.err
	}

	c.writeBuf = c.addHeader()
	_, _ = c.buffer.Write(c.writeBuf.Bytes())
	if c.buffer.Flush() != nil {
		return c.buffer.Flush()
	}

	c.writeBuf = nil

	return nil
}

func (c *Conn) addHeader() *bytes.Buffer {
	pl := uint64(c.writeBuf.Len())
	sId := uint64(c.sequenceId)
	c.sequenceId++

	plB := c.encFixedLenInt(pl, 3)
	sIdB := c.encFixedLenInt(sId, 1)

	return bytes.NewBuffer(append(append(plB, sIdB...), c.writeBuf.Bytes()...))
}

func (c *Conn) setupWriteBuffer() {
	if c.writeBuf == nil {
		c.writeBuf = bytes.NewBuffer(nil)
	}
}

type StatusFlags struct {
}

type OKPacket struct {
	PacketHeader
	Header           uint64
	AffectedRows     uint64
	LastInsertID     uint64
	StatusFlags      uint64
	Warnings         uint64
	Info             string
	SessionStateInfo string
}

func (c *Conn) decodeOKPacket(ph PacketHeader) (*OKPacket, error) {
	op := OKPacket{}
	op.PacketHeader = ph
	op.Header = ph.Status
	op.AffectedRows = c.getInt(TypeLenEncInt, 0)
	op.LastInsertID = c.getInt(TypeLenEncInt, 0)
	if c.HandshakeResponse.ClientFlag.Protocol41 {
		op.StatusFlags = c.getInt(TypeFixedInt, 2)
		op.Warnings = c.getInt(TypeFixedInt, 1)
	} else if c.HandshakeResponse.ClientFlag.Transactions {
		op.StatusFlags = c.getInt(TypeFixedInt, 2)
	}

	if c.HandshakeResponse.ClientFlag.SessionTrack {
		op.Info = c.getString(TypeRestOfPacketString, 0)
	} else {
		op.Info = c.getString(TypeRestOfPacketString, 0)
	}

	return &op, nil
}

type ErrorPacket struct {
	PacketHeader
	ErrorCode      uint64
	ErrorMessage   string
	SQLStateMarker string
	SQLState       string
}

func (c *Conn) decodeErrorPacket(ph PacketHeader) (*ErrorPacket, error) {
	ep := ErrorPacket{}
	ep.PacketHeader = ph
	ep.ErrorCode = c.getInt(TypeFixedInt, 2)
	ep.SQLStateMarker = c.getString(TypeFixedString, 1)
	ep.SQLState = c.getString(TypeFixedString, 5)
	ep.ErrorMessage = c.getString(TypeRestOfPacketString, 0)

	err := c.scanner.Err()
	if err != nil {
		return nil, err
	}

	return &ep, nil
}

func (c *Conn) setConnection(nc net.Conn) {
	c.curConn = nc

	c.buffer = bufio.NewReadWriter(
		bufio.NewReader(c.curConn),
		bufio.NewWriter(c.curConn),
	)

	c.scanner = bufio.NewScanner(c.buffer.Reader)
	c.scanner.Split(bufio.ScanBytes)
}
