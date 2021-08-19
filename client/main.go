package main

import (
	"net"

	"github.com/mowzhja/harpocrates/client/seshat"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9001")
	seshat.HandleErr(err)

	// sharedSecret, err := anubis.DoECDHE(conn)
	// seshat.HandleErr(err)

	// // TODO: get these as input/CLI arg
	// user := []byte("alice")
	// pass := []byte("alicespass")
	// err = cerberus.GetPeerData(conn, sharedSecret, user, pass)
	// seshat.HandleErr(err)

	conn.Close()
}
