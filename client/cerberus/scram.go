package cerberus

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/seshat"
	"golang.org/x/crypto/argon2"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func DoMutualAuth(conn net.Conn, sharedKey, uname, passwd []byte) error {
	cipher, err := anubis.NewCipher(sharedKey)
	if err != nil {
		return nil
	}

	err = scram(conn, cipher, uname, passwd)
	if err != nil {
		return nil
	}

	return nil
}

// Authenticates client and server to each other.
// Implements SCRAM authentication, as specified in RFC5802. Returns error if the authentication failed.
func scram(conn net.Conn, cipher anubis.Cipher, uname, passwd []byte) error {
	cdata := seshat.MergeChunks(cipher.Nonce(), uname)
	_, err := cipher.EncWrite(conn, cdata)
	if err != nil {
		return err
	}

	salt, snonce, err := doChallenge(conn, cipher)
	if err != nil {
		return err
	}

	err = cipher.UpdateNonce(snonce)
	if err != nil {
		return err
	}

	authMessage, servKey, err := computeParams(passwd, salt, cipher)
	if err != nil {
		return err
	}

	err = authClient(conn, authMessage, cipher)
	if err != nil {
		return err
	}

	err = authServer(conn, authMessage, servKey, cipher)
	if err != nil {
		return err
	}

	return nil
}

// Does the challenge part of the challenge-response authentication.
// Returns the salt and the server nonce and an error if anything went wrong.
func doChallenge(conn net.Conn, cipher anubis.Cipher) ([]byte, []byte, error) {
	sdata, _, err := cipher.DecRead(conn)
	if err != nil {
		return nil, nil, err
	}

	salt, snonce, err := extractDataNonce(sdata, 64)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(snonce[:32], cipher.Nonce()) != 1 {
		return nil, nil, errors.New("the server used the incorrect client nonce")
	}

	return salt, snonce, nil
}

// Computes the parameters used for SCRAM given the password and the salt.
// Returns the auth message, the server key and an error if anything goes wrong.
func computeParams(passwd, salt []byte, cipher anubis.Cipher) ([]byte, []byte, error) {
	saltedPasswd := argon2.Key(passwd, salt, 1, 2_000_000, 2, 32)

	clientKey := hmac.New(sha256.New, saltedPasswd)
	clientKey.Write([]byte("Client Key"))
	servKey := hmac.New(sha256.New, saltedPasswd)
	servKey.Write([]byte("Server Key"))

	storedKey := sha256.Sum256(clientKey.Sum(nil))
	clientSignature := hmac.New(sha256.New, storedKey[:])
	clientSignature.Write(cipher.Nonce())

	clientProof, err := seshat.XOR(clientSignature.Sum(nil), clientKey.Sum(nil))
	if err != nil {
		return nil, nil, err
	}
	authMessage := seshat.MergeChunks(cipher.Nonce(), clientProof)

	return authMessage, servKey.Sum(nil), nil
}

// Verifies the authenticity of the client.
// Returns the authMessage (for later use) and an error if the authentication failed for some reason (nil otherwise).
func authClient(conn net.Conn, authMessage []byte, cipher anubis.Cipher) error {

	// FIXME: m = nonce + [OK/FAIL]
	m, _, err := cipher.DecRead(conn)
	if err != nil {
		return err
	} else if string(m) != "OK" {
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

	serverSignature, _, err := cipher.DecRead(conn)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(expectedSignature, serverSignature) == 1 {
		// send OK
	} else {
		// send FAIL
		return errors.New("error authenticating the server (signatures don't match)")
	}

	return nil
}

// For convenience, extract the nonce and the data contained in a client message.
// Returns the data, the nonce and an error, in the order specified.
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

// Computes the server signature client-side.
// Returns the server signature and an error.
func getServerSignature(authMessage, servKey []byte) ([]byte, error) {
	serverSignature := hmac.New(sha256.New, servKey)
	n, err := serverSignature.Write(authMessage)
	if err != nil {
		return nil, err
	} else if n < 32 {
		return nil, errors.New("the signature should be 32 bytes (256 bits) long")
	}

	return serverSignature.Sum(nil), nil
}
