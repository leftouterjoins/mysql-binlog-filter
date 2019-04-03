package binlog

import (
	"bytes"
	"encoding/binary"
)

type HandshakePacket struct {
	PacketLength         uint64
	SequenceId           uint64
	ProtocolVersion      uint64
	ServerVersion        string
	ThreadId             uint64
	AuthPluginDataPart1  []byte
	CapabilityFlags1     []byte
	Charset              uint64
	Status               []byte
	CapabilityFlags2     []byte
	AuthPluginDataLength uint64
	AuthPluginDataPart2  []byte
	AuthPluginName       string
	CapabilityFlags      *CapabilityFlags
	StatusFlags          *StatusFlags
}

type CapabilityFlags struct {
	LongPassword               bool
	FoundRows                  bool
	LongFlag                   bool
	ConnectWithDb              bool
	NoSchema                   bool
	Compress                   bool
	Odbc                       bool
	LocalFiles                 bool
	IgnoreSpace                bool
	Protocol41                 bool
	Interactive                bool
	Ssl                        bool
	IgnoreSigpipe              bool
	Transactions               bool
	Reserved                   bool
	Reserved2                  bool
	MultiStatements            bool
	MultiResults               bool
	PsMultiResults             bool
	PluginAuth                 bool
	ConnectAttrs               bool
	PluginAuthLenEncClientData bool
	CanHandleExpiredPasswords  bool
	SessionTrack               bool
	DeprecateEOF               bool
	SslVerifyServerCert        bool
	OptionalResultSetMetadata  bool
	RememberOptions            bool
}

type StatusFlags struct {
	StatusInTrans            bool
	StatusAutocommit         bool
	MoreResultsExists        bool
	QueryNoGoodIndexUsed     bool
	QueryNoIndexUsed         bool
	StatusCursorExists       bool
	StatusLastRowSent        bool
	StatusDbDropped          bool
	StatusNoBackslashEscapes bool
	StatusMetadataChanged    bool
	QueryWasSlow             bool
	PsOutParams              bool
	StatusInTransReadonly    bool
	SessionStateChanged      bool
}

func (hs *HandshakePacket) decodeCapabilityFlags() {
	hs.CapabilityFlags = &CapabilityFlags{
		LongPassword:               (hs.CapabilityFlags1[0] & 1) > 0,
		FoundRows:                  (hs.CapabilityFlags1[0] & 2) > 0,
		LongFlag:                   (hs.CapabilityFlags1[0] & 4) > 0,
		ConnectWithDb:              (hs.CapabilityFlags1[0] & 8) > 0,
		NoSchema:                   (hs.CapabilityFlags1[0] & 16) > 0,
		Compress:                   (hs.CapabilityFlags1[0] & 32) > 0,
		Odbc:                       (hs.CapabilityFlags1[0] & 64) > 0,
		LocalFiles:                 (hs.CapabilityFlags1[0] & 128) > 0,
		IgnoreSpace:                (hs.CapabilityFlags1[1] & 1) > 0,
		Protocol41:                 (hs.CapabilityFlags1[1] & 2) > 0,
		Interactive:                (hs.CapabilityFlags1[1] & 4) > 0,
		Ssl:                        (hs.CapabilityFlags1[1] & 8) > 0,
		IgnoreSigpipe:              (hs.CapabilityFlags1[1] & 16) > 0,
		Transactions:               (hs.CapabilityFlags1[1] & 32) > 0,
		Reserved:                   (hs.CapabilityFlags1[1] & 64) > 0,
		Reserved2:                  (hs.CapabilityFlags1[1] & 128) > 0,
		MultiStatements:            (hs.CapabilityFlags2[0] & 1) > 0,
		MultiResults:               (hs.CapabilityFlags2[0] & 2) > 0,
		PsMultiResults:             (hs.CapabilityFlags2[0] & 4) > 0,
		PluginAuth:                 (hs.CapabilityFlags2[0] & 8) > 0,
		ConnectAttrs:               (hs.CapabilityFlags2[0] & 16) > 0,
		PluginAuthLenEncClientData: (hs.CapabilityFlags2[0] & 32) > 0,
		CanHandleExpiredPasswords:  (hs.CapabilityFlags2[0] & 64) > 0,
		SessionTrack:               (hs.CapabilityFlags2[0] & 128) > 0,
		DeprecateEOF:               (hs.CapabilityFlags2[1] & 1) > 0,
		SslVerifyServerCert:        (hs.CapabilityFlags2[1] & 2) > 0,
		OptionalResultSetMetadata:  (hs.CapabilityFlags2[1] & 4) > 0,
		RememberOptions:            (hs.CapabilityFlags2[1] & 8) > 0,
	}
}

func (hs *HandshakePacket) decodeStatusFlags() {
	hs.StatusFlags = &StatusFlags{
		StatusInTrans:            (hs.Status[0] & 1) > 0,
		StatusAutocommit:         (hs.Status[0] & 2) > 0,
		MoreResultsExists:        (hs.Status[0] & 4) > 0,
		QueryNoGoodIndexUsed:     (hs.Status[0] & 8) > 0,
		QueryNoIndexUsed:         (hs.Status[0] & 16) > 0,
		StatusCursorExists:       (hs.Status[0] & 32) > 0,
		StatusLastRowSent:        (hs.Status[0] & 64) > 0,
		StatusDbDropped:          (hs.Status[0] & 128) > 0,
		StatusNoBackslashEscapes: (hs.Status[1] & 1) > 0,
		StatusMetadataChanged:    (hs.Status[1] & 2) > 0,
		QueryWasSlow:             (hs.Status[1] & 4) > 0,
		PsOutParams:              (hs.Status[1] & 8) > 0,
		StatusInTransReadonly:    (hs.Status[1] & 16) > 0,
		SessionStateChanged:      (hs.Status[1] & 32) > 0,
	}
}

func (c *Conn) handshakePacket() (*HandshakePacket, error) {
	packet := HandshakePacket{}
	var err error

	packet.PacketLength, err = c.getInt(TypeFixedInt, 3)
	if err != nil {
		return nil, err
	}

	packet.SequenceId, err = c.getInt(TypeFixedInt, 1)
	if err != nil {
		return nil, err
	}

	packet.ProtocolVersion, err = c.getInt(TypeFixedInt, 1)
	if err != nil {
		return nil, err
	}

	packet.ServerVersion, err = c.getString(TypeNullTerminatedString, 0)
	if err != nil {
		return nil, err
	}

	packet.ThreadId, err = c.getInt(TypeFixedInt, 4)
	if err != nil {
		return nil, err
	}

	packet.AuthPluginDataPart1, err = c.getBytes(8)
	if err != nil {
		return nil, err
	}

	err = c.consumeBytes(1)
	if err != nil {
		return nil, err
	}

	packet.CapabilityFlags1, err = c.getBytes(2)
	if err != nil {
		return nil, err
	}

	packet.Charset, err = c.getInt(TypeFixedInt, 1)
	if err != nil {
		return nil, err
	}

	packet.Status, err = c.getBytes(2)
	if err != nil {
		return nil, err
	}

	packet.decodeStatusFlags()

	packet.CapabilityFlags2, err = c.getBytes(2)
	if err != nil {
		return nil, err
	}

	packet.decodeCapabilityFlags()

	packet.AuthPluginDataLength, err = c.getInt(TypeFixedInt, 1)
	if err != nil {
		return nil, err
	}

	err = c.consumeBytes(10)
	if err != nil {
		return nil, err
	}

	packet.AuthPluginDataPart2, err = c.getBytes(packet.AuthPluginDataLength - 8)
	if err != nil {
		return nil, err
	}

	packet.AuthPluginName, err = c.getString(TypeNullTerminatedString, 0)
	if err != nil {
		return nil, err
	}

	return &packet, nil
}

type HandshakeResponse struct {
	ClientFlag         *CapabilityFlags
	MaxPacketSize      uint64
	CharacterSet       uint64
	Username           string
	AuthResponseLength uint64
	AuthResponse       string
	Database           string
	ClientPluginName   string
	KeyValues          map[string]string
}

func (hr *HandshakeResponse) encode(c *Conn) []byte {
	buf := bytes.NewBuffer(make([]byte, 0))

	// Capabilities flag.
	flags := make([]byte, 4)
	if hr.ClientFlag.LongPassword {
		flags[0] |= 0x1
	}

	if hr.ClientFlag.FoundRows {
		flags[0] |= 0x2
	}

	if hr.ClientFlag.LongFlag {
		flags[0] |= 0x4
	}

	if hr.ClientFlag.ConnectWithDb {
		flags[0] |= 0x8
	}

	if hr.ClientFlag.NoSchema {
		flags[0] |= 0x10
	}

	if hr.ClientFlag.Compress {
		flags[0] |= 0x20
	}

	if hr.ClientFlag.Odbc {
		flags[0] |= 0x40
	}

	if hr.ClientFlag.LocalFiles {
		flags[0] |= 0x80
	}

	if hr.ClientFlag.IgnoreSpace {
		flags[1] |= 0x1
	}

	if hr.ClientFlag.Protocol41 {
		flags[1] |= 0x2
	}

	if hr.ClientFlag.Interactive {
		flags[1] |= 0x4
	}

	if hr.ClientFlag.Ssl {
		flags[1] |= 0x8
	}

	if hr.ClientFlag.IgnoreSigpipe {
		flags[1] |= 0x10
	}

	if hr.ClientFlag.Transactions {
		flags[1] |= 0x20
	}

	if hr.ClientFlag.Reserved {
		flags[1] |= 0x40
	}

	if hr.ClientFlag.Reserved2 {
		flags[1] |= 0x80
	}

	if hr.ClientFlag.MultiStatements {
		flags[2] |= 0x1
	}

	if hr.ClientFlag.MultiResults {
		flags[2] |= 0x2
	}

	if hr.ClientFlag.PsMultiResults {
		flags[2] |= 0x4
	}

	if hr.ClientFlag.PluginAuth {
		flags[2] |= 0x8
	}

	if hr.ClientFlag.ConnectAttrs {
		flags[2] |= 0x10
	}

	if hr.ClientFlag.PluginAuthLenEncClientData {
		flags[2] |= 0x20
	}

	if hr.ClientFlag.CanHandleExpiredPasswords {
		flags[2] |= 0x40
	}

	if hr.ClientFlag.SessionTrack {
		flags[2] |= 0x80
	}

	if hr.ClientFlag.DeprecateEOF {
		flags[3] |= 0x1
	}

	if hr.ClientFlag.SslVerifyServerCert {
		flags[3] |= 0x2
	}

	if hr.ClientFlag.OptionalResultSetMetadata {
		flags[3] |= 0x4
	}

	if hr.ClientFlag.RememberOptions {
		flags[3] |= 0x8
	}

	// Write Capability Flags.
	buf.Write(flags)

	// Write MaxPacketSize
	mps := make([]byte, 4)
	binary.LittleEndian.PutUint32(mps, uint32(MaxPacketSize))
	buf.Write(mps)

	// Write CharacterSet
	cs := make([]byte, 2)
	binary.LittleEndian.PutUint16(cs, uint16(hr.CharacterSet))
	buf.Write(cs[:1])

	// Write Filler
	buf.Write(make([]byte, 23))

	// Write username
	u := append([]byte(hr.Username), NullByte)
	buf.Write(u)

	if hr.ClientFlag.PluginAuthLenEncClientData {

	}

	// Write database name
	if hr.ClientFlag.ConnectWithDb {
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

func (c *Conn) handshakeResponse() *HandshakeResponse {
	return &HandshakeResponse{
		ClientFlag: &CapabilityFlags{
			LongPassword:               true,
			FoundRows:                  true,
			LongFlag:                   true,
			ConnectWithDb:              true,
			NoSchema:                   false,
			Compress:                   true,
			Odbc:                       false,
			LocalFiles:                 false,
			IgnoreSpace:                true,
			Protocol41:                 true,
			Interactive:                true,
			Ssl:                        c.Config.SSL,
			IgnoreSigpipe:              false,
			Transactions:               true,
			Reserved:                   false,
			Reserved2:                  false,
			MultiStatements:            false,
			MultiResults:               false,
			PsMultiResults:             true,
			PluginAuth:                 true,
			ConnectAttrs:               false,
			PluginAuthLenEncClientData: true,
			CanHandleExpiredPasswords:  false,
			SessionTrack:               true,
			DeprecateEOF:               true,
			SslVerifyServerCert:        c.Config.VerifyCert,
			OptionalResultSetMetadata:  true,
			RememberOptions:            true,
		},
		MaxPacketSize:      MaxPacketSize,
		CharacterSet:       45,
		Username:           c.Config.User,
		AuthResponseLength: 4,
		AuthResponse:       "root",
		Database:           c.Config.Database,
		ClientPluginName:   c.Handshake.AuthPluginName,
		KeyValues:          nil,
	}
}
