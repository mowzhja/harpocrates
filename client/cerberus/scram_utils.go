package cerberus

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"

	"github.com/mowzhja/harpocrates/client/anubis"
	"github.com/mowzhja/harpocrates/client/seshat"
	"golang.org/x/crypto/argon2"
)

// Computes the parameters used for SCRAM given the password and the salt.
// Returns the auth message, the server key and an error if anything goes wrong.
func computeParams(passwd, salt, nonce []byte) ([]byte, []byte, error) {
	if len(passwd) == 0 || len(salt) == 0 {
		return nil, nil, errors.New("password, salt or both are empty")
	}
	if len(nonce) != 64 {
		return nil, nil, errors.New("the nonce must be 64 bytes long")
	}

	saltedPasswd := argon2.Key(passwd, salt, 1, 2_000_000, 2, 32)

	clientKey := hmac.New(sha256.New, saltedPasswd)
	clientKey.Write([]byte("Client Key"))
	servKey := hmac.New(sha256.New, saltedPasswd)
	servKey.Write([]byte("Server Key"))

	storedKey := sha256.Sum256(clientKey.Sum(nil))
	clientSignature := hmac.New(sha256.New, storedKey[:])
	clientSignature.Write(nonce)

	clientProof, err := seshat.XOR(clientSignature.Sum(nil), clientKey.Sum(nil))
	if err != nil {
		return nil, nil, err
	}
	authMessage := seshat.MergeChunks(nonce, clientProof)

	return authMessage, servKey.Sum(nil), nil
}

// Wrapper around DecRead() to check the nonce as well as reading the message every time we read from remote.
// Returns the message enclosed in the stream, the number of bytes read and an error.
func checkRead(conn net.Conn, cipher anubis.Cipher) ([]byte, int, error) {
	m, _, err := cipher.DecRead(conn)
	if err != nil {
		return nil, 0, err
	}

	msg, nonce, err := extractDataNonce(m, 64)
	if err != nil {
		return nil, 0, err
	}

	if subtle.ConstantTimeCompare(cipher.Nonce(), nonce) != 1 {
		return nil, 0, errors.New("the nonces don't match")
	}

	return msg, len(msg), nil
}

// Wrapper around EncWrite, automatically creates the nonce+msg data to send to the server and does the sending.
// Returns number of bytes send and an error.
func fullWrite(conn net.Conn, msg []byte, cipher anubis.Cipher) (int, error) {
	data := seshat.MergeChunks(cipher.Nonce(), msg)
	n, err := cipher.EncWrite(conn, data)
	if err != nil {
		return 0, err
	}

	return n, nil
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