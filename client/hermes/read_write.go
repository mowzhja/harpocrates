package hermes

import (
	"bufio"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"strings"

	"github.com/mowzhja/harpocrates/client/anubis"
	"github.com/mowzhja/harpocrates/client/seshat"
)

// Wrapper around DecRead() to check the nonce as well as reading the message every time we read from remote.
// Returns the message enclosed in the stream, the number of bytes read and an error.
func FullRead(conn net.Conn, cipher anubis.Cipher) ([]byte, int, error) {
	m, _, err := DecRead(conn, cipher)
	if err != nil {
		return nil, 0, err
	}

	msg, nonce, err := seshat.ExtractDataNonce(m, 64)
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
func FullWrite(conn net.Conn, msg []byte, cipher anubis.Cipher) (int, error) {
	data := seshat.MergeChunks(cipher.Nonce(), msg)
	n, err := EncWrite(conn, cipher, data)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func EncWrite(conn net.Conn, cipher anubis.Cipher, plaintext []byte) (int, error) {
	aeadtext := cipher.Encrypt(plaintext)

	return Write(conn, aeadtext)
}

// Wrapper around conn.Read() to make sure we read decrypted data.
func DecRead(conn net.Conn, cipher anubis.Cipher) ([]byte, int, error) {
	m, nr, err := Read(conn)
	if err != nil {
		return nil, 0, err
	}
	plaintext, err := cipher.Decrypt(m)

	return plaintext, nr, err
}

// Wrapper to write accross a TCP connection.
// To mantain consistency with the net API, it returns the number of bytes written and an error.
func Write(conn net.Conn, msg []byte) (int, error) {
	writer := bufio.NewWriter(conn)
	hexMsg := hex.EncodeToString(msg) + string('\n')

	n, err := writer.WriteString(hexMsg)
	if err != nil {
		return 0, err
	}

	err = writer.Flush()
	if err != nil {
		return 0, err
	}

	return n, nil
}

// Wrapper to read data accross a TCP connection.
// To mantain the API consistent with the net API, on top of returning the message read from the connection it returns the number of bytes read and an error.
func Read(conn net.Conn) ([]byte, int, error) {
	hexMsg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, 0, err
	}

	msg, err := hex.DecodeString(strings.TrimSuffix(hexMsg, "\n"))
	if err != nil {
		return nil, 0, err
	}

	return msg, len(msg), err
}
