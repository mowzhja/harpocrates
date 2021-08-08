package anubis

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"net"

	"github.com/mowzhja/harpocrates/server/hermes"
)

type Cipher struct {
	key   []byte
	nonce []byte
	aead  cipher.AEAD
}

const BYTE_SEC = 32 // 32 * 8 == 256

// Creates a new Cipher given the key.
// Returns the Cipher and nil in case of a success, an empty Cipher and an error otherwise.
func NewCipher(k []byte) (Cipher, error) {
	n := make([]byte, BYTE_SEC)
	_, err := rand.Read(n)
	if err != nil {
		return Cipher{}, err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return Cipher{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Cipher{}, err
	}

	return Cipher{
		key:   k,
		nonce: n,
		aead:  gcm,
	}, nil
}

// Wrapper around hermes.Write() to make sure we send encrypted data over the channel.
func (c *Cipher) EncWrite(conn net.Conn, plaintext []byte) (int, error) {
	aeadtext := c.encrypt(plaintext)
	return hermes.Write(conn, aeadtext)
}

// Wrapper around hermes.Read() to make sure we read encrypted data.
func (c *Cipher) DecRead(conn net.Conn) ([]byte, int, error) {
	ciphertext, nr, err := hermes.Read(conn)
	if err != nil {
		return nil, 0, err
	}
	plaintext, err := c.decrypt(ciphertext)

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
