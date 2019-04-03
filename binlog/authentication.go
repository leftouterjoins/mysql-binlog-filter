package binlog

import (
	"crypto/sha256"
)

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

func (c *Conn) sha256Hash(word []byte) []byte {
	s := sha256.New()
	s.Write(word)
	return s.Sum(nil)
}
