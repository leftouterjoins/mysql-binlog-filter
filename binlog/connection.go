package binlog

import (
	"bufio"
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"time"
)

// MySQL Packet Data Types
const TypeNullTerminatedString = int(0)
const TypeFixedString = int(1)
const TypeFixedInt = int(2)

//const TypeLenEncodedInt = int(3)

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

func newBinlogConfig(dsn string) (*Config, error) {
	var err error

	config := Config{}
	err = json.Unmarshal([]byte(dsn), &config)

	return &config, err
}

type Conn struct {
	Config    *Config
	tcpConn   *net.TCPConn
	Handshake *Handshake
	buffer    *bufio.ReadWriter
}

func newBinlogConn(config *Config) Conn {
	return Conn{
		Config: config,
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
	fmt.Printf("%+v", c.Handshake)
	//b := c.encodeHandshakeResponse()
	//fmt.Printf("%08b\n%d\n%s", b, b, b)

	//_, err = c.tcpConn.Write(b)

	return c, err
}

func init() {
	sql.Register("mysql-binlog", &Driver{})
}

func (c *Conn) getPacketLength() uint64 {
	l := c.getInt(TypeFixedInt, 3)
	return l
}

func (c *Conn) readWholePacket() (*bytes.Buffer, error) {
	pl := c.getPacketLength()
	b, err := c.readBytes(pl - 3)
	return b, err
}

func (c *Conn) readBytes(l uint64) (*bytes.Buffer, error) {
	if c.buffer == nil {
		c.buffer = bufio.NewReadWriter(
			bufio.NewReader(c.tcpConn),
			bufio.NewWriter(c.tcpConn),
		)
	}

	b := make([]byte, l)
	_, err := c.buffer.Read(b)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(b), nil
}

func (c *Conn) getBytes(l uint64) *bytes.Buffer {
	b := make([]byte, l)
	_, _ = c.buffer.Read(b)
	return bytes.NewBuffer(b)
}

func (c *Conn) getBytesUntilNull() *bytes.Buffer {
	s, _ := c.buffer.ReadBytes(NullByte)
	return bytes.NewBuffer(s)
}

func (c *Conn) discardBytes(l int) {
	_, _ = c.buffer.Discard(l)
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
	return string(b.Bytes())
}

func (c *Conn) decFixedString(l uint64) string {
	b, _ := c.readBytes(l)
	return b.String()
}

func (c *Conn) decFixedInt(l uint64) uint64 {
	b, _ := c.readBytes(l)

	var i uint64
	i, _ = binary.ReadUvarint(b)

	return i
}

func (c *Conn) encFixedLenInt(l uint64, v uint64) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint64(b, v)
	return b[:(l - 1)]
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

	b = append(prefix, b...)
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
