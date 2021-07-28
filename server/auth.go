package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func doMutualAuth(conn net.Conn, sharedKey []byte) error {
	nonce := make([]byte, 32)
	keySha := sha256.Sum256(sharedKey)

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	_, err = rand.Read(nonce)
	if err != nil {
		return nil
	}

	servSecret, err := xor(nonce, keySha[:])
	if err != nil {
		return nil
	}

	err = doChallenge(conn, cipher, nonce, servSecret)
	if err != nil {
		return nil
	}

	err = doAuth(conn, cipher)
	if err != nil {
		return nil
	}

	return nil
}

// Responsible for the challenge part.
func doChallenge(conn net.Conn, cipher cipher.AEAD, nonce, m []byte) error {
	clientSecret := make([]byte, len(nonce))
	expected := sha256.Sum256(nonce) // the value i expect to get from the client

	ciphertext := cipher.Seal(nil, nonce, m, nil)
	_, err := conn.Write(ciphertext)
	if err != nil {
		return nil
	}

	_, err = conn.Read(clientSecret)
	if err != nil {
		return nil
	}

	if subtle.ConstantTimeCompare(expected[:], clientSecret) != 1 {
		return errors.New("client authentication failed")
	}

	return nil
}

// Authenticates client and server to each other.
// TODO: actually implement all the parts
func doAuth(conn net.Conn, cipher cipher.AEAD) error {
	uname := make([]byte, 255) // FIXME: that's probably the wrong size

	// TODO: build wrappers around read/write + encryption/decryption
	_, err := conn.Read(uname)
	if err != nil {
		return err
	}

	getCorrespondingInfo(uname) // TODO:

	_, err := conn.Write(salt + dataForArgon2)
	if err != nil {
		return err
	}

	_, err := conn.Read(clientProof)
	if err != nil {
		return err
	}

	err = verify(clientProof)
	if err != nil {
		return err
	}

	return nil
}

func verify() error {
	computeClientSig()
	getClientKey() // from XOR
	checkClientKey(StoredKey)

	return nil
}
