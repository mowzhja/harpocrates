package cerberus

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"

	"github.com/mowzhja/harpocrates/client/anubis"
	"github.com/mowzhja/harpocrates/client/hermes"
	"github.com/mowzhja/harpocrates/client/seshat"
)

// Authenticates client and server to each other.
// Implements SCRAM authentication, as specified in RFC5802. Returns error if the authentication failed.
func scram(conn net.Conn, cipher anubis.Cipher, uname, passwd []byte) ([]byte, error) {
	_, err := hermes.FullWrite(conn, uname, cipher)
	if err != nil {
		return nil, err
	}

	salt, snonce, err := doChallenge(conn, cipher)
	if err != nil {
		return nil, err
	}
	fmt.Println("[+] Challenge successful...")

	// from this point forth the nonce is 64 bytes long (client + server)
	err = cipher.UpdateNonce(snonce)
	if err != nil {
		return nil, err
	}

	authMessage, servKey, clientKey, err := computeParams(passwd, salt, cipher.Nonce())
	if err != nil {
		return nil, err
	}

	err = authClient(conn, authMessage, cipher)
	if err != nil {
		return nil, err
	}
	fmt.Println("[+] Client authentication successful...")

	err = authServer(conn, authMessage, servKey, cipher)
	if err != nil {
		return nil, err
	}
	fmt.Println("[+] Server authentication successful...")

	return clientKey, nil
}

// Does the challenge part of the challenge-response authentication.
// Returns the salt and the server nonce and an error if anything went wrong.
func doChallenge(conn net.Conn, cipher anubis.Cipher) ([]byte, []byte, error) {
	sdata, _, err := hermes.DecRead(conn, cipher)
	if err != nil {
		return nil, nil, err
	}

	salt, snonce, err := seshat.ExtractDataNonce(sdata, 64)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(snonce[:32], cipher.Nonce()) != 1 {
		return nil, nil, errors.New("the server used the incorrect client nonce")
	}

	return salt, snonce, nil
}

// Verifies the authenticity of the client.
// Returns the authMessage (for later use) and an error if the authentication failed for some reason (nil otherwise).
func authClient(conn net.Conn, authMessage []byte, cipher anubis.Cipher) error {
	_, err := hermes.EncWrite(conn, cipher, authMessage)
	if err != nil {
		return err
	}

	resp, _, err := hermes.FullRead(conn, cipher)
	if err != nil {
		return err
	}
	if string(resp) != "SERVER_OK" {
		return errors.New("client authentication failed")
	}

	return nil
}

// Sends the necesarry info for server authentication to the client.
// Returns an error in case there was a problem with any of the steps or if server authentication failed client-side.
func authServer(conn net.Conn, authMessage, servKey []byte, cipher anubis.Cipher) error {
	expectedSignature, err := getServerSignature(authMessage, servKey)
	if err != nil {
		return err
	}

	serverSignature, _, err := hermes.FullRead(conn, cipher)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(expectedSignature, serverSignature) == 1 {
		_, err := hermes.FullWrite(conn, []byte("CLIENT_OK"), cipher)
		if err != nil {
			return err
		}
	} else {
		_, err := hermes.FullWrite(conn, []byte("CLIENT_FAIL"), cipher)
		if err != nil {
			return err
		}

		return errors.New("error authenticating the server (signatures don't match)")
	}

	return nil
}
