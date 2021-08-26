package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mowzhja/harpocrates/client/cerberus"
	"github.com/mowzhja/harpocrates/client/hermes"
	"github.com/mowzhja/harpocrates/client/seshat"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9001")
	seshat.HandleErr(err)

	sharedSecret, err := hermes.DoECDHE(conn)
	seshat.HandleErr(err)

	user := os.Args[1]
	pass := os.Args[2]
	// peerAddr is a multiaddress (check out firefox)
	_, _, peerAddr, err := cerberus.AuthWithServer(conn, sharedSecret, []byte(user), []byte(pass))
	seshat.HandleErr(err)

	// close connection to server
	conn.Close()

	fmt.Printf("\n[+] Initiating peer to peer connection with %s...\n", peerAddr)
	time.Sleep(10 * time.Second)
}
