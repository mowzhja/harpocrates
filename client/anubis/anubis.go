// Anubis is the Egyptian god of the underworld, but i used his name because of this: https://en.wikipedia.org/wiki/Anubis_(cipher)
// Package anubis implements all the cryptography needed for the project.
package anubis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha512"
	"math/rand"
	"net"

	"github.com/mowzhja/harpocrates/client/hermes"
	"github.com/mowzhja/harpocrates/client/seshat"
)

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

// Responsible for the actual ECDHE.
// Returns the shared secret (the key for symmetric crypto) and an error if anything goes wrong.
func DoECDHE(conn net.Conn) ([]byte, error) {
	E := elliptic.P521()

	privKey, pubKey, err := generateKeys(E)
	seshat.HandleErr(err)

	_, err = hermes.Write(conn, pubKey)
	seshat.HandleErr(err)

	serverPub, _, err := hermes.Read(conn)
	seshat.HandleErr(err)

	sharedSecret, err := calculateSharedSecret(E, serverPub, privKey)
	seshat.HandleErr(err)

	sharedKey := sha512.Sum512_256(sharedSecret)

	return sharedKey[:], nil
}
