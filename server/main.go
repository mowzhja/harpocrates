package main

import (
	"fmt"
	"net"
	"os"
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

func handleErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func handleClient(conn net.Conn) error {
	defer conn.Close()
	var buf []byte

	_, err := conn.Read(buf)
	handleErr(err)

	privBytes, x, y, pubBytes, err := cm.generateKeys()
	handleErr(err)

	sharedSecret, err := cm.calculateSecret(buf, privBytes, x, y)
	handleErr(err)

	fmt.Printf("shared secret: %x\n", sharedSecret)

	_, err = conn.Write(pubBytes)
	handleErr(err)

	return nil
}
