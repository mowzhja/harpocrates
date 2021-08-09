package cerberus

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/coeus"
	"github.com/mowzhja/harpocrates/server/seshat"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func DoMutualAuth(conn net.Conn, sharedKey []byte) error {
	cipher, err := anubis.NewCipher(sharedKey)
	if err != nil {
		return nil
	}

	err = scram(conn, cipher)
	if err != nil {
		return nil
	}

	return nil
}

// Authenticates client and server to each other.
// Implements SCRAM authentication, as specified in RFC5802. Returns error if the authentication failed.
func scram(conn net.Conn, cipher anubis.Cipher) error {
	cdata, _, err := cipher.DecRead(conn) // read client nonce and username
	if err != nil {
		return err
	}

	uname, cnonce, err := extractDataNonce(cdata, 32)
	if err != nil {
		return err
	}

	// suppose client and server agree on the KDF parameters already
	salt, storedKey, servKey, err := coeus.GetCorrespondingInfo(string(uname))
	if err != nil {
		return err
	}

	authMessage, err := doChallenge(conn, cnonce, salt, cipher)
	if err != nil {
		return err
	}

	// in my implementation AuthMessage == nonce + ClientProof
	err = authClient(authMessage, storedKey)
	if err != nil {
		// FIXME: fix this, keep the idea same
		_, nonce := extractDataNonce(authMessage)
		failMsg := seshat.Merge(nonce, []byte("failed"))
		cipher.EncWrite(conn, failMsg)
		return err
	}

	err = authServer(conn, authMessage, servKey, cipher)
	if err != nil {
		return err
	}

	return nil
}

// Does the challenge part of the challenge-response authentication.
// Returns the authMessage of the client and an error (nil if all is good).
func doChallenge(conn net.Conn, cnonce, salt []byte, cipher anubis.Cipher) ([]byte, error) {
	snonce := make([]byte, 32)
	_, err := rand.Read(snonce)
	if err != nil {
		return nil, err
	}

	snonce = seshat.MergeChunks(cnonce, snonce) // nonce used for the rest of the authentication procedure (by both client and server)

	sdata := seshat.MergeChunks(cnonce, salt)
	_, err = cipher.EncWrite(conn, sdata)
	if err != nil {
		return nil, err
	}

	authMessage, _, err := cipher.DecRead(conn)
	if err != nil {
		return nil, err
	}

	_, cnonce, err = extractDataNonce(authMessage, 64)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(cnonce, snonce) != 1 {
		return nil, errors.New("the client and server nonces don't match")
	}

	return authMessage, nil
}

// Verifies the authenticity of the client.
// Returns an error if the authentication failed for some reason (nil otherwise).
func authClient(authMessage, storedKey []byte) error {
	// authMessage is just nonce + clientProof
	clientProof, nonce, err := extractDataNonce(authMessage, 64)
	if err != nil {
		return err
	}

	clientSignature := hmac.New(sha256.New, storedKey)
	clientSignature.Write(nonce) // ! changed from the RFC !

	clientKey, err := seshat.XOR(clientSignature.Sum(nil), clientProof)
	if err != nil {
		return err
	}

	expectedKey := sha256.Sum256(clientKey)
	eq := subtle.ConstantTimeCompare(storedKey, expectedKey[:])
	if eq != 1 {
		return errors.New("stored key and the client key don't match")
	}

	return nil
}

// Sends the necesarry info for server authentication to the client.
// Returns an error in case there was a problem with any of the steps or if server authentication failed client-side.
func authServer(conn net.Conn, authMessage, servKey []byte, cipher anubis.Cipher) error {
	serverSignature, err := getServerSig(authMessage, servKey)
	if err != nil {
		return err
	}

	_, snonce, err := extractDataNonce(authMessage, 64)
	if err != nil {
		return err
	}
	// so the client can authenticate the server
	sdata := seshat.MergeChunks(snonce, serverSignature)
	_, err = cipher.EncWrite(conn, sdata)
	if err != nil {
		return err
	}

	// TODO: add some code with which the client can confirm server auth

	return nil
}

// For convenience, extract the nonce and the data contained in a client message.
// Returns the data, the nonce and an error (nil if all good), in the order specified.
func extractDataNonce(cdata []byte, nlen int) ([]byte, []byte, error) {
	if !(nlen == 32 || nlen == 64) {
		return nil, nil, errors.New("nonce must be either 32 or 64 bytes long")
	} else if len(cdata) < nlen {
		return nil, nil, errors.New("data is too short")
	}
	nonce := cdata[:nlen]
	rest := cdata[nlen:]

	return rest, nonce, nil
}

// Computes server signature given client proof and server key.
// Returns the server signature and an error (nil if everything is good).
func getServerSig(authMessage, servKey []byte) ([]byte, error) {
	serverSignature := hmac.New(sha256.New, servKey)
	n, err := serverSignature.Write(authMessage)
	if err != nil {
		return nil, err
	} else if n < 32 {
		return nil, errors.New("the signature should be 32 bytes (256 bits) long")
	}

	return serverSignature.Sum(nil), nil
}
