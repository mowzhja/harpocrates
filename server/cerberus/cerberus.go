package cerberus

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func doMutualAuth(conn net.Conn, sharedKey []byte) error {
	cipher, err := server.NewCipher(sharedKey)
	if err != nil {
		return nil
	}

	err = SCRAM(conn, cipher)
	if err != nil {
		return nil
	}

	return nil
}

// Authenticates client and server to each other.
// Implements SCRAM authentication, as specified in RFC5802. Returns error if the authentication failed.
func SCRAM(conn net.Conn, cipher Cipher) error {
	cdata, _, err := cipher.decRead(conn) // read client nonce and username
	if err != nil {
		return err
	}

	uname, cnonce := extractDataNonce(cdata, 32)

	// suppose client and server agree on the KDF parameters already
	// => no need to send them
	salt, storedKey, servKey := getCorrespondingInfo(string(uname))

	snonce := make([]byte, 32)
	_, err = rand.Read(snonce)
	if err != nil {
		return err
	}

	snonce = mergeChunks(cnonce, snonce) // nonce used for the rest of the authentication procedure (by both client and server)

	sdata := mergeChunks(cnonce, salt)
	_, err = cipher.encWrite(conn, sdata)
	if err != nil {
		return err
	}

	cdata, _, err = cipher.decRead(conn)
	if err != nil {
		return err
	}
	clientProof, cnonce := extractDataNonce(cdata, 64)
	if subtle.ConstantTimeCompare(cnonce, snonce) != 1 {
		return errors.New("the client and server nonces don't match")
	}

	err = verify(clientProof, storedKey)
	if err != nil {
		return err
	}

	serverSignature := hmac.New(sha256.New, clientProof)
	serverSignature.Write(servKey)

	// so the client can authenticate the server
	sdata = mergeChunks(snonce, serverSignature.Sum(nil))
	_, err = cipher.encWrite(conn, sdata)
	if err != nil {
		return err
	}

	return nil
}

// Verifies the authenticity of the client.
// Returns an error if the authentication failed for some reason.
func verify(clientProof, storedKey []byte) error {
	clientSignature := hmac.New(sha256.New, clientProof)
	clientSignature.Write(storedKey)

	clientKey, err := xor(clientSignature.Sum(nil), clientProof)
	if err != nil {
		return err
	}

	eq := subtle.ConstantTimeCompare(storedKey, sha256.New().Sum(clientKey))
	if eq != 1 {
		return errors.New("the stored key and the client key don't match")
	}

	return nil
}

// For convenience, extract the nonce and the data contained in a client message.
func extractDataNonce(cdata []byte, nlen int) ([]byte, []byte) {
	nonce := cdata[:nlen] // the nonce is the first 32/64 bytes
	rest := cdata[(nlen + 1):]

	return rest, nonce
}
