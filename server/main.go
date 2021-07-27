package main

import (
	"net"
)

func main() {
	// TODO possibly given by CLI
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9001")
	handleErr(err)

	listener, err := net.ListenTCP("tcp", addr)
	handleErr(err)

	for {
		conn, err := listener.Accept()
		handleErr(err)

		// goroutine
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) error {
	defer conn.Close()

	sharedKey, err := doECDHE(conn)
	handleErr(err)

	err = doMutualAuth(conn, sharedKey)
	handleErr(err)

	return nil
}
