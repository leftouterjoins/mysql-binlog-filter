package binlog

import (
	"crypto/sha1"
	"crypto/sha256"
)

func (c *Conn) authenticate(hr *HandshakeResponse) {
	switch c.Handshake.AuthPluginName {
	case "mysql_native_password":
		c.doSha1Auth(hr)
	case "caching_sha2_password":
		c.doSha2Auth(hr)
	}
}

func (c *Conn) doSha1Auth(hr *HandshakeResponse) {
}

func (c *Conn) doSha2Auth(hr *HandshakeResponse) {
	salt := append(c.Handshake.AuthPluginDataPart1.Bytes(), c.Handshake.AuthPluginDataPart2.Bytes()...)
	ar := c.cachingSha2Auth(salt, []byte(hr.AuthResponse))
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

func (c *Conn) nativeSha1Auth() {
	// SHA1(password) XOR SHA1("20-bytes random data from server" <concat> SHA1(SHA1(password)))

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
