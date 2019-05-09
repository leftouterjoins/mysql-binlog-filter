package binlog

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
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

type SSLRequest struct {
	ClientFlag    *Capabilities
	MaxPacketSize uint64
	CharacterSet  uint64
	Username      string
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
	p1l := uint64(packet.AuthPluginDataPart1.Len())
	packet.AuthPluginDataPart2 = c.readBytes(packet.AuthPluginDataLength - p1l)
	packet.AuthPluginName = c.getString(TypeNullTerminatedString, 0)

	err := c.scanner.Err()
	if err != nil {
		return err
	}

	c.Handshake = &packet

	return nil
}

func (c *Conn) writeHandshakeResponse() error {
	hr := c.HandshakeResponse
	cf := c.structToBitmask(hr.ClientFlag)
	c.putBytes(cf)
	c.putInt(TypeFixedInt, hr.MaxPacketSize, 4)
	c.putInt(TypeFixedInt, hr.CharacterSet, 1)
	c.putNullBytes(23)
	c.putString(TypeNullTerminatedString, hr.Username)

	// Perform authentication
	salt := append(c.Handshake.AuthPluginDataPart1.Bytes(), c.Handshake.AuthPluginDataPart2.Bytes()...)
	password := []byte(hr.AuthResponse)
	c.authenticate(salt, password)

	// Write database name
	if hr.ClientFlag.ConnectWithDB {
		c.putString(TypeNullTerminatedString, hr.Database)
	}

	// Set type of auth plugin based on if it is at the end of the packet.
	var t int
	if hr.KeyValues != nil {
		t = TypeNullTerminatedString
	} else {
		t = TypeRestOfPacketString
	}

	// Write auth plugin
	if hr.ClientFlag.PluginAuth {
		c.putString(t, hr.ClientPluginName)

		c.putNullBytes(1)
	}

	if c.Flush() != nil {
		return c.Flush()
	}

	return nil
}

func (c *Conn) writeSSLRequestPacket() error {
	sr := c.NewSSLRequest()
	cf := c.structToBitmask(sr.ClientFlag)
	c.putBytes(cf)
	c.putInt(TypeFixedInt, sr.MaxPacketSize, 4)
	c.putInt(TypeFixedInt, sr.CharacterSet, 1)
	c.putNullBytes(23)

	if c.Flush() != nil {
		return c.Flush()
	}

	return nil
}

func (c *Conn) NewSSLRequest() *SSLRequest {
	return &SSLRequest{
		ClientFlag:    c.HandshakeResponse.ClientFlag,
		MaxPacketSize: c.HandshakeResponse.MaxPacketSize,
		CharacterSet:  c.HandshakeResponse.CharacterSet,
		Username:      c.HandshakeResponse.Username,
	}
}

func (c *Conn) NewHandshakeResponse() *HandshakeResponse {
	return &HandshakeResponse{
		ClientFlag: &Capabilities{
			LongPassword:               true,
			FoundRows:                  true,
			LongFlag:                   false,
			ConnectWithDB:              false,
			NoSchema:                   false,
			Compress:                   false,
			ODBC:                       false,
			LocalFiles:                 false,
			IgnoreSpace:                true,
			Protocol41:                 true,
			Interactive:                true,
			SSL:                        c.Config.SSL,
			IgnoreSigpipe:              false,
			Transactions:               c.Handshake.Capabilities.Transactions,
			LegacyProtocol41:           false,
			SecureConnection:           true,
			MultiStatements:            false,
			MultiResults:               false,
			PSMultiResults:             true,
			PluginAuth:                 c.Handshake.Capabilities.PluginAuth,
			ConnectAttrs:               false,
			PluginAuthLenEncClientData: false,
			CanHandleExpiredPasswords:  false,
			SessionTrack:               c.Handshake.Capabilities.SessionTrack,
			DeprecateEOF:               false,
			SSLVerifyServerCert:        c.Config.VerifyCert,
			OptionalResultSetMetadata:  false,
			RememberOptions:            false,
		},
		MaxPacketSize:      MaxPacketSize,
		CharacterSet:       45,
		Username:           c.Config.User,
		AuthResponseLength: 0,
		AuthResponse:       c.Config.Pass,
		Database:           c.Config.Database,
		ClientPluginName:   c.Handshake.AuthPluginName,
		KeyValues:          nil,
	}
}

// generate TLS config for client side
// if insecureSkipVerify is set to true, serverName will not be validated
func NewClientTLSConfig(keyPem string, cerPem string, caPem []byte, insecureSkipVerify bool, serverName string) *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: !insecureSkipVerify,
		ServerName:         serverName,
	}

	if caPem != nil {
		ca, err := ioutil.ReadFile(string(caPem))
		if err == nil {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				panic("failed to add ca PEM")
			}

			config.RootCAs = pool
		}
	}

	if keyPem != "" && cerPem != "" {
		cert, err := tls.LoadX509KeyPair(cerPem, keyPem)
		if err != nil {
			panic(err)
		}

		config.Certificates = []tls.Certificate{cert}
	}

	return config
}
