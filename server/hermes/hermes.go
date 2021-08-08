// Package hermes implements functionality related to the TCP connection between client and server (seeing as Hermes is the god of travelers and boundaries (among other things)).
package hermes

import (
	"bufio"
	"encoding/hex"
	"net"
)

// Wrapper to write accross a TCP connection.
// To mantain consistency with the net API, it returns the number of bytes written and an error.
func Write(conn net.Conn, msg []byte) (int, error) {
	msg = append(msg, '\n')
	n, err := bufio.NewWriter(conn).Write(msg)
	if err != nil {
		return 0, err
	}

	return n, nil
}

// Wrapper to read data accross a TCP connection.
// To mantain the API consistent with the net API, on top of returning the message read from the connection it returns the number of bytes read and an error.
func Read(conn net.Conn) (int, error, []byte) {
	hexMsg, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return 0, err, nil
	}

	var msg []byte
	n, err := hex.Decode(msg, hexMsg)
	if err != nil {
		return 0, err, nil
	}

	return n, nil, msg
}
