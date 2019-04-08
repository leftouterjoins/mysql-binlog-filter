package binlog

import (
	"bytes"
	"encoding/binary"
)

type Capabilities struct {
	LongPassword               bool
	FoundRows                  bool
	LongFlag                   bool
	ConnectWithDB              bool
	NoSchema                   bool
	Compress                   bool
	ODBC                       bool
	LocalFiles                 bool
	IgnoreSpace                bool
	Protocol41                 bool
	Interactive                bool
	SSL                        bool
	IgnoreSigpipe              bool
	Transactions               bool
	LegacyProtocol41           bool
	SecureConnection           bool
	MultiStatements            bool
	MultiResults               bool
	PSMultiResults             bool
	PluginAuth                 bool
	ConnectAttrs               bool
	PluginAuthLenEncClientData bool
	CanHandleExpiredPasswords  bool
	SessionTrack               bool
	DeprecateEOF               bool
	SSLVerifyServerCert        bool
	OptionalResultSetMetadata  bool
	RememberOptions            bool
}

type Status struct {
	InTrans              bool
	Autocommit           bool
	MoreResultsExists    bool
	QueryNoGoodIndexUsed bool
	QueryNoIndexUsed     bool
	CursorExists         bool
	LastRowSent          bool
	DBDropped            bool
	NoBackslashEscapes   bool
	MetadataChanged      bool
	QueryWasSlow         bool
	PSOutParams          bool
	InTransReadonly      bool
	SessionStateChanged  bool
}

type Handshake struct {
	PacketLength         uint64
	SequenceID           uint64
	ProtocolVersion      uint64
	ServerVersion        string
	ThreadID             uint64
	AuthPluginDataPart1  *bytes.Buffer
	CapabilityFlags1     *bytes.Buffer
	Charset              uint64
	StatusFlags          *bytes.Buffer
	CapabilityFlags2     *bytes.Buffer
	AuthPluginDataLength uint64
	AuthPluginDataPart2  *bytes.Buffer
	AuthPluginName       string
	Capabilities         *Capabilities
	Status               *Status
}

type HandshakeResponse struct {
	ClientFlag         *Capabilities
	MaxPacketSize      uint64
	CharacterSet       uint64
	Username           string
	AuthResponseLength uint64
	AuthResponse       string
	Database           string
	ClientPluginName   string
	KeyValues          map[string]string
}

func (c *Conn) decodeCapabilityFlags(hs *Handshake) {
	var cfb = append(hs.CapabilityFlags1.Bytes(), hs.CapabilityFlags2.Bytes()...)
	capabilities := c.bitmaskToStruct(cfb, hs.Capabilities).(Capabilities)
	hs.Capabilities = &capabilities
}

func (c *Conn) decodeStatusFlags(hs *Handshake) {
	status := c.bitmaskToStruct(hs.StatusFlags.Bytes(), hs.Status).(Status)
	hs.Status = &status
}

func (c *Conn) decodeHandshakePacket() error {
	packet := Handshake{}

	packet.PacketLength = c.getInt(TypeFixedInt, 3)
	packet.SequenceID = c.getInt(TypeFixedInt, 1)
	packet.ProtocolVersion = c.getInt(TypeFixedInt, 1)
	packet.ServerVersion = c.getString(TypeNullTerminatedString, 0)
	packet.ThreadID = c.getInt(TypeFixedInt, 4)
	packet.AuthPluginDataPart1 = c.readBytes(8)
	c.discardBytes(1)
	packet.CapabilityFlags1 = c.readBytes(2)
	packet.Charset = c.getInt(TypeFixedInt, 1)
	packet.StatusFlags = c.readBytes(2)
	c.decodeStatusFlags(&packet)
	packet.CapabilityFlags2 = c.readBytes(2)
	c.decodeCapabilityFlags(&packet)
	packet.AuthPluginDataLength = c.getInt(TypeFixedInt, 1)
	c.discardBytes(10)
	packet.AuthPluginDataPart2 = c.readBytes(packet.AuthPluginDataLength - 8)
	packet.AuthPluginName = c.getString(TypeNullTerminatedString, 0)

	if c.scanner.Err() != nil {
		return c.scanner.Err()
	}

	c.Handshake = &packet

	return nil
}

func (c *Conn) encodeHandshakeResponse() []byte {
	hr := NewHandshakeResponse()
	buf := bytes.NewBuffer(make([]byte, 0))

	// Capabilities flag.
	var cf capability = 0

	// Write Capability Flags.
	buf.Write([]byte(cf))

	// Write MaxPacketSize
	buf.Write(MaxPacketSize)

	// Write CharacterSet
	cs := make([]byte, 2)
	binary.LittleEndian.PutUint16(cs, uint16(hr.CharacterSet))
	buf.Write(cs[:1])

	// Write Filler
	buf.Write(make([]byte, 23))

	// Write username
	u := append([]byte(hr.Username), NullByte)
	buf.Write(u)

	salt := append(c.Handshake.AuthPluginDataPart1.Bytes(), c.Handshake.AuthPluginDataPart2.Bytes()...)
	ar := c.cachingSha2Auth(salt, []byte(hr.AuthResponse))
	if hr.ClientFlag.PluginAuthLenEncClientData {
		buf.Write(c.encLenEncInt(uint64(len(ar))))
		buf.Write(ar)
	} else if hr.ClientFlag.SecureConnection {
		l := make([]byte, 2)
		binary.LittleEndian.PutUint16(l, uint16(len(ar)))
		buf.Write(l[:1])
		buf.Write(ar)
	} else {
		buf.Write(append(ar, NullByte))
	}

	// Write database name
	if hr.ClientFlag.ConnectWithDB {
		buf.Write(append([]byte(hr.Database), NullByte))
	}

	// Write auth plugin
	if hr.ClientFlag.PluginAuth {
		buf.Write([]byte(hr.ClientPluginName))
	}

	pl := make([]byte, 4)
	binary.LittleEndian.PutUint32(pl, uint32(buf.Len()))
	p := append(pl[:3], 1)
	p = append(p, buf.Bytes()...)
	buf = bytes.NewBuffer(p)

	return buf.Bytes()
}

func NewHandshakeResponse() *HandshakeResponse {
	return &HandshakeResponse{
		ClientFlag: &Capabilities{
			LongPassword:               true,
			FoundRows:                  true,
			LongFlag:                   true,
			ConnectWithDB:              true,
			NoSchema:                   false,
			Compress:                   false,
			ODBC:                       false,
			LocalFiles:                 false,
			IgnoreSpace:                true,
			Protocol41:                 true,
			Interactive:                true,
			SSL:                        false,
			IgnoreSigpipe:              false,
			Transactions:               true,
			LegacyProtocol41:           false,
			SecureConnection:           true,
			MultiStatements:            false,
			MultiResults:               false,
			PSMultiResults:             true,
			PluginAuth:                 false,
			ConnectAttrs:               false,
			PluginAuthLenEncClientData: false,
			CanHandleExpiredPasswords:  false,
			SessionTrack:               true,
			DeprecateEOF:               true,
			SSLVerifyServerCert:        false,
			OptionalResultSetMetadata:  true,
			RememberOptions:            true,
		},
		MaxPacketSize:      MaxPacketSize,
		CharacterSet:       45,
		Username:           "",
		AuthResponseLength: 0,
		AuthResponse:       "",
		Database:           "",
		ClientPluginName:   "",
		KeyValues:          nil,
	}
}
