package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
)

// Implements the mutual challenge-response auth between server and clients.
func doMutualAuth(conn net.Conn, sharedKey []byte) error {
	nonce := make([]byte, 32)
	keySha := sha256.Sum256(sharedKey)

	cipher, err := aes.NewCipher(sharedKey)
	returnErr(err)
	_, err = rand.Read(nonce)
	returnErr(err)

	expected, err := xor(nonce, keySha[:])
	returnErr(err)

	err = doChallenge(conn, nonce, expected)
	returnErr(err)

	return nil
}

// Responsible for the challenge part.
func doChallenge(conn net.Conn, n, expected []byte) error {
	buf := make([]byte, len(n))

	_, err := conn.Write(n)
	returnErr(err)

	_, err = conn.Read(buf)
	returnErr(err)

	if subtle.ConstantTimeCompare(expected, buf) != 1 {
		return errors.New("client authentication failed")
	}
	return nil
}
