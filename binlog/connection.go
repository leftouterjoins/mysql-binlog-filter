package binlog

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const NullByte byte = '\x00'
const MaxPacketSize = 16777216

// MySQL Packet Data Types
const TypeNullTerminatedString = int(0)
const TypeFixedString = int(1)
const TypeFixedInt = int(2)
const TypeLenEncodedInt = int(3)

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
	Handshake *HandshakePacket
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

	blConn := newBinlogConn(config)

	dialer := net.Dialer{Timeout: blConn.Config.Timeout}
	addr := fmt.Sprintf("%s:%d", blConn.Config.Host, blConn.Config.Port)
	c, err := dialer.Dial("tcp", addr)
	blConn.tcpConn = c.(*net.TCPConn)

	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Temporary() {
			fmt.Printf("Error: %s", netErr.Error())
			return nil, err
		}
	}

	hsp, err := blConn.handshakePacket()
	blConn.Handshake = hsp

	resp := blConn.handshakeResponse()
	b := resp.encode(&blConn)
	fmt.Printf("%d", b)
	_, err = blConn.tcpConn.Write(b)

	return blConn, err
}

func init() {
	sql.Register("mysql-binlog", &Driver{})
}

func (c *Conn) getBytes(l uint64) ([]byte, error) {
	b := make([]byte, l)
	_, err := c.tcpConn.Read(b)

	return b, err
}

func (c *Conn) consumeBytes(l uint64) error {
	b := make([]byte, l)
	_, err := c.tcpConn.Read(b)

	return err
}

func (c *Conn) getInt(t int, l uint64) (uint64, error) {
	var v uint64
	var err error = nil

	switch t {
	case TypeFixedInt:
		v, err = c.popFixedInt(l)
	default:
		v = 0
	}

	if err != nil {
		return 0, err
	}

	return v, nil
}

func (c *Conn) getString(t int, l uint64) (string, error) {
	var v string
	var err error = nil

	switch t {
	case TypeFixedString:
		v, err = c.popFixedString(l)
	case TypeNullTerminatedString:
		v, err = c.popNullTerminatedString()
	default:
		v = ""
	}

	if err != nil {
		return "", err
	}

	return v, nil
}

func (c *Conn) readBytes(l uint64) (*bytes.Buffer, error) {
	b := make([]byte, l)
	_, err := c.tcpConn.Read(b)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(b), nil
}

func (c *Conn) readToNull() (*bytes.Buffer, error) {
	var s []byte
	for {
		bA := make([]byte, 1)
		_, err := c.tcpConn.Read(bA)
		if err != nil {
			return nil, err
		}

		b := bA[0]
		if b == NullByte {
			break
		} else {
			s = append(s, b)
		}
	}

	return bytes.NewBuffer(s), nil
}

func (c *Conn) popNullTerminatedString() (string, error) {
	b, err := c.readToNull()
	if err != nil {
		return "", err
	}

	return string(b.Bytes()), nil
}

func (c *Conn) popFixedString(l uint64) (string, error) {
	b, err := c.readBytes(l)
	if err != nil {
		return "", err
	}

	return string(b.Bytes()), nil
}

func (c *Conn) popFixedInt(l uint64) (uint64, error) {
	b, err := c.readBytes(l)
	if err != nil {
		return 0, err
	}

	var i uint64
	i, err = binary.ReadUvarint(b)

	return i, err
}
