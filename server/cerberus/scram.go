package cerberus

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/coeus"
	"github.com/mowzhja/harpocrates/server/hermes"
	"github.com/mowzhja/harpocrates/server/seshat"
)

// Authenticates client and server to each other.
// Implements SCRAM authentication, as specified in RFC5802. Returns error if the authentication failed.
func scram(conn net.Conn, cipher anubis.Cipher) error {
	cdata, _, err := hermes.DecRead(conn, cipher) // read client nonce and username
	if err != nil {
		return err
	}

	uname, cnonce, err := seshat.ExtractDataNonce(cdata, 32)
	if err != nil {
		return err
	}

	// suppose client and server agree on the KDF parameters already
	salt, storedKey, servKey, err := coeus.GetCorrespondingInfo(string(uname))
	if err != nil {
		return err
	}

	fmt.Println(hex.EncodeToString(salt))

	clientProof, nonce, err := doChallenge(conn, cnonce, salt, cipher)
	if err != nil {
		return err
	}

	err = cipher.UpdateNonce(nonce)
	// notify the client of how the challenge went
	if err != nil {
		_, err = hermes.FullWrite(conn, []byte("SERVER_FAIL"), cipher)
		if err != nil {
			return err
		}
		return err
	}
	if err == nil {
		_, err = hermes.FullWrite(conn, []byte("SERVER_OK"), cipher)
		if err != nil {
			return err
		}
	}

	fmt.Println("succ challenge")
	err = authClient(clientProof, cipher.Nonce(), storedKey)
	if err != nil {
		fmt.Println(err)
		_, err = hermes.FullWrite(conn, []byte("SERVER_FAIL"), cipher)
		if err != nil {
			return err
		}
		return err
	} else {
		_, err = hermes.FullWrite(conn, []byte("SERVER_OK"), cipher)
		if err != nil {
			return err
		}
	}

	err = authServer(conn, clientProof, servKey, cipher)
	if err != nil {
		return err
	}

	return nil
}

// Does the challenge part of the challenge-response authentication.
// Returns the client proof, the shared nonce and an error (nil if all is good).
func doChallenge(conn net.Conn, cnonce, salt []byte, cipher anubis.Cipher) ([]byte, []byte, error) {
	snonce := make([]byte, 32)
	_, err := rand.Read(snonce)
	if err != nil {
		return nil, nil, err
	}

	snonce = seshat.MergeChunks(cnonce, snonce) // nonce used for the rest of the authentication procedure (by both client and server)

	sdata := seshat.MergeChunks(snonce, salt)
	_, err = hermes.EncWrite(conn, cipher, sdata)
	if err != nil {
		return nil, nil, err
	}

	authMessage, _, err := hermes.DecRead(conn, cipher)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println("am", len(authMessage))

	clientProof, cnonce, err := seshat.ExtractDataNonce(authMessage, 64)
	if err != nil {
		return nil, nil, err
	}

	if subtle.ConstantTimeCompare(cnonce, snonce) != 1 {
		return nil, nil, errors.New("the client and server nonces don't match")
	}

	fmt.Println("cp", len(clientProof))
	return clientProof, snonce, nil
}

// Verifies the authenticity of the client.
// Returns an error if the authentication failed for some reason (nil otherwise).
func authClient(clientProof, nonce, storedKey []byte) error {
	clientSignature := hmac.New(sha256.New, storedKey)
	clientSignature.Write(nonce) // ! changed from the RFC !

	fmt.Println("cs", len(clientSignature.Sum(nil)))
	fmt.Println("cp", len(clientProof))
	clientKey, err := seshat.XOR(clientSignature.Sum(nil), clientProof)
	if err != nil {
		return err
	}

	fmt.Println(hex.EncodeToString(storedKey))

	expectedKey := sha256.Sum256(clientKey)
	if subtle.ConstantTimeCompare(storedKey, expectedKey[:]) != 1 {
		return errors.New("stored key and the client key don't match")
	}

	return nil
}

// Sends the necessary info for server authentication to the client.
// Returns an error in case there was a problem with any of the steps or if server authentication failed client-side.
func authServer(conn net.Conn, clientProof, servKey []byte, cipher anubis.Cipher) error {
	authMessage := seshat.MergeChunks(cipher.Nonce(), clientProof)
	serverSignature, err := seshat.GetServerSignature(authMessage, servKey)
	if err != nil {
		return err
	}

	fmt.Println(hex.EncodeToString(serverSignature))

	_, err = hermes.FullWrite(conn, serverSignature, cipher)
	if err != nil {
		return err
	}

	resp, _, err := hermes.FullRead(conn, cipher)
	if err != nil {
		return err
	}
	if string(resp) != "CLIENT_OK" {
		return errors.New("server authentication failed")
	}

	return nil
}
