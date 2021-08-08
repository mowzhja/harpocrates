package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	privBytes, x, y, pubBytes, err := generateKeys()
	handleErr(err)

	buf := make([]byte, len(pubBytes))

	conn, err := net.Dial("tcp", "127.0.0.1:9001")
	handleErr(err)
	defer conn.Close()

	_, err = conn.Write(pubBytes[:])
	handleErr(err)

	_, err = conn.Read(buf[:])
	handleErr(err)

	sharedSecret, err := anubis.calculateSharedSecret(buf, privBytes, x, y)
	handleErr(err)

	fmt.Printf("shared secret: %x\n", sharedSecret)
}

func handleErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal error: %s", err.Error())
		os.Exit(1)
	}
}
