package main

import (
	"fmt"
	"net"

	"github.com/mowzhja/harpocrates/client/anubis"
	"github.com/mowzhja/harpocrates/client/seshat"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9001")
	seshat.HandleErr(err)
	defer conn.Close()

	sharedSecret, err := anubis.DoECDHE(conn)
	seshat.HandleErr(err)

	fmt.Printf("shared secret: %x\n", sharedSecret)
}
