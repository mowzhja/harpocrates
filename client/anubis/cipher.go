package anubis

import (
	"crypto/cipher"
	"errors"
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

// Wrapper around encryption.
func (c *Cipher) Encrypt(plaintext []byte) []byte {
	nonce := c.nonce[:c.aead.NonceSize()]
	return c.aead.Seal(nil, nonce, plaintext, nil)
}

// Wrapper around decryption.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	nonce := c.nonce[:c.aead.NonceSize()]
	return c.aead.Open(nil, nonce, ciphertext, nil)
}
