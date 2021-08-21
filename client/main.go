package main

import (
	"net"

	"github.com/mowzhja/harpocrates/client/cerberus"
	"github.com/mowzhja/harpocrates/client/hermes"
	"github.com/mowzhja/harpocrates/client/seshat"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9001")
	seshat.HandleErr(err)

	sharedSecret, err := hermes.DoECDHE(conn)
	seshat.HandleErr(err)

	// TODO: get these as input/CLI arg
	user := []byte("alice")
	pass := []byte("alicespass")
	// peerAddr is a multiaddress (check out firefox)
	ownClientKey, peerStoredKey, peerAddr, err := cerberus.AuthWithServer(conn, sharedSecret, user, pass)
	seshat.HandleErr(err)

	// close connection to server
	conn.Close()

	hermes.PeerToPeer(ownClientKey, peerStoredKey, peerAddr)

}
