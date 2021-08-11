package anubis

import (
	"crypto/cipher"
	"errors"
	"net"

	"github.com/mowzhja/harpocrates/client/hermes"
)

type Cipher struct {
	key   []byte
	nonce []byte
	aead  cipher.AEAD
}

const BYTE_SEC = 32 // 32 * 8 == 256

// Returns the nonce of a Cipher.
func (c *Cipher) Nonce() []byte {
	return c.nonce
}

// Updates the nonce of a given cipher.
func (c *Cipher) UpdateNonce(newNonce []byte) error {
	c.nonce = newNonce
	if string(c.nonce) != string(newNonce) {
		return errors.New("failed to update the nonce")
	}

	return nil
}

// Wrapper around conn.Write() to make sure we send encrypted data over the channel.
func (c *Cipher) EncWrite(conn net.Conn, plaintext []byte) (int, error) {
	aeadtext := c.encrypt(plaintext)

	return hermes.Write(conn, aeadtext)
}

// Wrapper around conn.Read() to make sure we read decrypted data.
func (c *Cipher) DecRead(conn net.Conn) ([]byte, int, error) {
	m, nr, err := hermes.Read(conn)
	if err != nil {
		return nil, 0, err
	}
	plaintext, err := c.decrypt(m)

	return plaintext, nr, err
}

// Wrapper around encryption.
func (c *Cipher) encrypt(plaintext []byte) []byte {
	nonce := c.nonce[:c.aead.NonceSize()]
	return c.aead.Seal(nil, nonce, plaintext, nil)
}

// Wrapper around decryption.
func (c *Cipher) decrypt(ciphertext []byte) ([]byte, error) {
	nonce := c.nonce[:c.aead.NonceSize()]
	return c.aead.Open(nil, nonce, ciphertext, nil)
}
