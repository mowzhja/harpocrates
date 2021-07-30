package main

import (
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

	cipher, err := NewCipher(sharedKey)

	servSecret, err := xor(nonce, keySha[:])
	if err != nil {
		return nil
	}

	err = doChallenge(conn, cipher, servSecret)
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
func doChallenge(conn net.Conn, cipher Cipher, m []byte) error {
	expected := sha256.Sum256(cipher.getNonce()) // from client

	_, err := cipher.encWrite(conn, m)
	if err != nil {
		return err
	}

	clientSecret, _, err := cipher.decRead(conn)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(expected[:], clientSecret) != 1 {
		return errors.New("client authentication failed")
	}

	return nil
}

// Authenticates client and server to each other.
// TODO: actually implement all the parts
func doAuth(conn net.Conn, cipher Cipher) error {
	uname, _, err := cipher.decRead(conn)
	if err != nil {
		return err
	}

	// suppose client and server agree on the KDF parameters already
	// => no need to send them
	salt, storedKey, servKey := getCorrespondingInfo(string(uname))
	data := mergeChunks(salt, storedKey)
	_, err = cipher.encWrite(conn, data)
	if err != nil {
		return err
	}

	clientProof, _, err := cipher.decRead(conn)
	if err != nil {
		return err
	}

	err = verify(clientProof, servKey)
	if err != nil {
		return err
	}

	return nil
}

func verify(clientProof, servKey []byte) error {
	computeClientSig()
	getClientKey() // from XOR
	checkClientKey(StoredKey)

	return nil
}
