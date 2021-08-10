// Package hermes implements functionality related to the TCP connection between client and server (seeing as Hermes is the god of travelers and boundaries (among other things)).
package hermes

import (
	"bufio"
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
func Read(conn net.Conn) ([]byte, int, error) {
	msg, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, 0, err
	}

	return msg, len(msg), err
}
