package cerberus

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"

	"github.com/mowzhja/harpocrates/server/coeus"
	"github.com/mowzhja/harpocrates/server/seshat"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func DoMutualAuth(conn net.Conn, sharedKey []byte) error {
	cipher, err := seshat.NewCipher(sharedKey)
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
func scram(conn net.Conn, cipher seshat.Cipher) error {
	cdata, _, err := cipher.DecRead(conn) // read client nonce and username
	if err != nil {
		return err
	}

	uname, cnonce, err := extractDataNonce(cdata, 32)
	if err != nil {
		return err
	}

	// suppose client and server agree on the KDF parameters already
	salt, storedKey, servKey := coeus.GetCorrespondingInfo(string(uname))

	clientProof, snonce, err := doChallenge(conn, cnonce, salt, cipher)
	if err != nil {
		return err
	}

	err = authClient(clientProof, storedKey)
	if err != nil {
		return err
	}

	err = authServer(conn, clientProof, servKey, snonce, cipher)
	if err != nil {
		return err
	}

	return nil
}

// Does the challenge part of the challenge-response authentication.
func doChallenge(conn net.Conn, cnonce, salt []byte, cipher seshat.Cipher) ([]byte, []byte, error) {
	snonce := make([]byte, 32)
	_, err := rand.Read(snonce)
	if err != nil {
		return nil, nil, err
	}

	snonce = seshat.MergeChunks(cnonce, snonce) // nonce used for the rest of the authentication procedure (by both client and server)

	sdata := seshat.MergeChunks(cnonce, salt)
	_, err = cipher.EncWrite(conn, sdata)
	if err != nil {
		return nil, nil, err
	}

	cdata, _, err := cipher.DecRead(conn)
	if err != nil {
		return nil, nil, err
	}

	clientProof, cnonce, err := extractDataNonce(cdata, 64)
	if err != nil {
		return nil, nil, err
	}

	if subtle.ConstantTimeCompare(cnonce, snonce) != 1 {
		return nil, nil, errors.New("the client and server nonces don't match")
	}

	return clientProof, snonce, nil
}

// Verifies the authenticity of the client.
// Returns an error if the authentication failed for some reason.
func authClient(clientProof, storedKey []byte) error {
	clientSignature := hmac.New(sha256.New, clientProof)
	clientSignature.Write(storedKey)

	clientKey, err := seshat.XOR(clientSignature.Sum(nil), clientProof)
	if err != nil {
		return err
	}

	eq := subtle.ConstantTimeCompare(storedKey, sha256.New().Sum(clientKey))
	if eq != 1 {
		return errors.New("the stored key and the client key don't match")
	}

	return nil
}

// Sends the necesarry info for server authentication to the client.
// Returns an error in case there was a problem with any of the steps or if server authentication failed client-side.
func authServer(conn net.Conn, clientProof, servKey, snonce []byte, cipher seshat.Cipher) error {
	serverSignature, err := getServerSig(clientProof, servKey)
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
func getServerSig(clientProof, servKey []byte) ([]byte, error) {
	serverSignature := hmac.New(sha256.New, clientProof)
	n, err := serverSignature.Write(servKey)
	if err != nil {
		return nil, err
	} else if n < 32 {
		return nil, errors.New("the signature should be 32 bytes (256 bits) long")
	}

	return serverSignature.Sum(nil), nil
}
