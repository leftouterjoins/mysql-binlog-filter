package binlog

import (
	"bufio"
	"bytes"
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

// MySQL Packet Data Types
const TypeNullTerminatedString = int(0)
const TypeFixedString = int(1)
const TypeFixedInt = int(2)
const TypeLenEncInt = int(3)
const TypeRestOfPacketString = int(4)

// Integer Maximums
const MaxUint8 = 1<<8 - 1
const MaxUint16 = 1<<16 - 1
const MaxUint24 = 1<<24 - 1
const MaxUint64 = 1<<64 - 1

// Misc. Constants
const NullByte byte = 0
const MaxPacketSize = MaxUint16

type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Pass       string `json:"password"`
	Database   string `json:"database"`
	SSL        bool   `json:"ssl"`
	VerifyCert bool   `json:"verify_cert"`
	Timeout    time.Duration
}

func splitByBytesFunc(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF {
		return 0, nil, errors.New("scanner found EOF")
	}

	return 1, data[:1], nil
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
	Config     *Config
	tcpConn    *net.TCPConn
	Handshake  *Handshake
	buffer     *bufio.ReadWriter
	scanner    *bufio.Scanner
	err        error
	sequenceId uint64
	writeBuf   *bytes.Buffer
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

	dialer := net.Dialer{Timeout: c.Config.Timeout}
	addr := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)
	t, err := dialer.Dial("tcp", addr)
	c.tcpConn = t.(*net.TCPConn)

	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Temporary() {
			fmt.Printf("Error: %s", netErr.Error())
			return nil, err
		}
	}

	err = c.decodeHandshakePacket()
	if err != nil {
		return nil, err
	}

	err = c.writeHandshakeResponse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("%+v\n", c.Handshake)
	return c, err
}

func init() {
	sql.Register("mysql-binlog", &Driver{})
}

func (c *Conn) readBytes(l uint64) *bytes.Buffer {
	if c.buffer == nil {
		c.buffer = bufio.NewReadWriter(
			bufio.NewReader(c.tcpConn),
			bufio.NewWriter(c.tcpConn),
		)

		c.scanner = bufio.NewScanner(c.buffer.Reader)
		c.scanner.Split(splitByBytesFunc)
	}

	b := make([]byte, 0)
	for i := uint64(0); i < l; i++ {
		c.scanner.Scan()
		b = append(b, c.scanner.Bytes()...)
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

func (c *Conn) discardBytes(l int) {
	for i := 0; i < l; i++ {
		c.scanner.Scan()
	}
}

func (c *Conn) getInt(t int, l uint64) uint64 {
	var v uint64

	switch t {
	case TypeFixedInt:
		v = c.decFixedInt(l)
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
	case TypeNullTerminatedString:
		v = c.decNullTerminatedString()
	default:
		v = ""
	}

	return v
}

func (c *Conn) decNullTerminatedString() string {
	b := c.getBytesUntilNull()
	return strings.TrimRight(b.String(), string(NullByte))
}

func (c *Conn) decFixedString(l uint64) string {
	b := c.readBytes(l)
	return b.String()
}

func (c *Conn) decFixedInt(l uint64) uint64 {
	var i uint64
	b := c.readBytes(l)
	i, _ = binary.ReadUvarint(b)
	return i
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
	case v < MaxUint8:
		b = make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(v))
		b = b[:1]
	case v >= MaxUint8 && v < MaxUint16:
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
