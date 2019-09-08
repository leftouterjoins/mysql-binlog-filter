package binlog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
)

// Sha2RequestPublicKey is a constant in the MySQL Protocol.
const Sha2RequestPublicKey = 0x02

// Sha2FastAuthSuccess is a constant in the MySQL Protocol.
const Sha2FastAuthSuccess = 0x03

// Sha2PerformFullAuthentication is a constant in the MySQL protocol.
const Sha2PerformFullAuthentication = 0x04

// AuthMoreDataPacket represnts a MySQL auth-more packet.
type AuthMoreDataPacket struct {
	*PacketHeader
	Data uint64
}

func (c *Conn) decodeAuthMoreDataResponsePacket(ph *PacketHeader) (*AuthMoreDataPacket, error) {
	md := AuthMoreDataPacket{}
	md.PacketHeader = ph
	md.Data = c.getInt(TypeFixedInt, 1)

	err := c.scanner.Err()
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// AuthResponsePacket represents a MySQL authentication response packet.
type AuthResponsePacket struct {
	PacketLength   uint64
	SequenceID     uint64
	Status         uint64
	PluginName     string
	AuthPluginData *bytes.Buffer
}

func (c *Conn) decodeAuthResponsePacket() (*AuthResponsePacket, error) {
	packet := AuthResponsePacket{}

	packet.PacketLength = c.getInt(TypeFixedInt, 3)
	packet.SequenceID = c.getInt(TypeFixedInt, 1)
	packet.Status = c.getInt(TypeFixedInt, 1)
	packet.PluginName = c.getString(TypeNullTerminatedString, 0)
	packet.AuthPluginData = c.readBytes(20)

	err := c.scanner.Err()
	if err != nil {
		return nil, err
	}

	return &packet, err
}

func (c *Conn) writeAuthSwitchPacket(ap *AuthResponsePacket) error {
	salt := ap.AuthPluginData.Bytes()
	password := []byte(c.HandshakeResponse.AuthResponse)
	c.authenticate(salt, password)

	if c.Flush() != nil {
		return c.Flush()
	}

	return nil
}

func (c *Conn) authenticate(salt []byte, password []byte) {
	var ar []byte

	salt = salt[:20] // trim null byte from end.
	switch c.Handshake.AuthPluginName {
	case "mysql_native_password":
		ar = c.nativeSha1Auth(salt, password)
	case "caching_sha2_password":
		ar = c.cachingSha2Auth(salt, password)
	}

	hr := c.HandshakeResponse
	hr.AuthResponseLength = uint64(len(ar))
	if hr.ClientFlag.PluginAuthLenEncClientData {
		c.putInt(TypeLenEncInt, hr.AuthResponseLength, 0)
		c.putBytes(ar)
	} else if hr.ClientFlag.SecureConnection {
		c.putInt(TypeFixedInt, hr.AuthResponseLength, 1)
		c.putBytes(ar)
	} else {
		c.putString(TypeNullTerminatedString, string(ar))
	}
}

func (c *Conn) nativeSha1Auth(salt []byte, password []byte) []byte {
	if len(password) < 1 {
		return nil
	}

	pHash := c.sha1Hash(password)
	pHashHash := c.sha1Hash(pHash)
	spHash := c.sha1Hash(append(salt, pHashHash...))

	for i := range pHash {
		pHash[i] ^= spHash[i]
	}

	return pHash
}

func (c *Conn) cachingSha2Auth(salt []byte, password []byte) []byte {
	if len(password) < 1 {
		return nil
	}

	pHash := c.sha256Hash(password)
	pHashHash := c.sha256Hash(pHash)
	pHashHashHash := c.sha256Hash(pHashHash)
	authData := c.sha256Hash(append(pHashHashHash, salt...))

	for i := range pHash {
		pHash[i] ^= authData[i]
	}

	return pHash
}

func (c *Conn) sha1Hash(word []byte) []byte {
	s := sha1.New()
	s.Write(word)
	return s.Sum(nil)
}

func (c *Conn) sha256Hash(word []byte) []byte {
	s := sha256.New()
	s.Write(word)
	return s.Sum(nil)
}
