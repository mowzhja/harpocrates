// Anubis is the Egyptian god of the underworld, but i used his name because of this: https://en.wikipedia.org/wiki/Anubis_(cipher)
// Package anubis implements all the cryptography needed for the project.
package anubis

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math/rand"
)

// Creates a new Cipher given the key.
// Returns the Cipher and nil in case of a success, an empty Cipher and an error otherwise.
func NewCipher(k []byte) (Cipher, error) {
	if len(k) != BYTE_SEC {
		return Cipher{}, errors.New("the key must be 32 bytes long")
	}

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
