package cerberus

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/seshat"
)

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
