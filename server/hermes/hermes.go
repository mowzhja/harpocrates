// Package hermes implements functionality related to the TCP connection between client and server (seeing as Hermes is the god of travelers and boundaries (among other things)).
package hermes

import (
	"bufio"
	"encoding/hex"
	"net"
	"strings"
)

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
