package seshat

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"net"
)

type Cipher struct {
	key   []byte
	nonce []byte
	aead  cipher.AEAD
}

// Creates a new Cipher given the key
// Returns the Cipher and nil in case of a success, an empty Cipher and an error otherwise
func NewCipher(k []byte) (Cipher, error) {
	n := make([]byte, 32)
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

// Wrapper around conn.Write() to make sure we send encrypted data over the channel.
// IMPORTANT: this method assumes that the plaintext is of sufficient size to be transmitted all at once, so fragmentation must happen elsewhere!
func (c *Cipher) EncWrite(conn net.Conn, plaintext []byte) (int, error) {
	aeadtext := c.encrypt(plaintext)
	return conn.Write(aeadtext)
}

// Wrapper around conn.Read() to make sure we read decrypted data.
// IMPORTANT: this method assumes that the ciphertext is of sufficient size to be read all at once, so fragmentation must happen elsewhere!
func (c *Cipher) DecRead(conn net.Conn) ([]byte, int, error) {
	m := make([]byte, 1000) // FIXME: hermes.PACKET_SIZE

	nr, err := conn.Read(m)
	if err != nil {
		return nil, 0, err
	}
	plaintext, err := c.decrypt(m)

	return plaintext, nr, err
}

// Wrapper around encryption.
func (c *Cipher) encrypt(plaintext []byte) []byte {
	return c.aead.Seal(nil, c.nonce, plaintext, nil)
}

// Wrapper around decryption.
func (c *Cipher) decrypt(ciphertext []byte) ([]byte, error) {
	return c.aead.Open(nil, c.nonce, ciphertext, nil)
}
