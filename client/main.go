package main

import (
	"net"

	"github.com/mowzhja/harpocrates/client/anubis"
	"github.com/mowzhja/harpocrates/client/cerberus"
	"github.com/mowzhja/harpocrates/client/seshat"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9001")
	seshat.HandleErr(err)

	sharedSecret, err := anubis.DoECDHE(conn)
	seshat.HandleErr(err)

	user := []byte("test")
	pass := []byte("testpass")
	err = cerberus.DoMutualAuth(conn, sharedSecret, user, pass)
	seshat.HandleErr(err)

	conn.Close()
}
