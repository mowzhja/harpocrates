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
	ownClientKey, peerStoredKey, peerIP, err := cerberus.AuthWithServer(conn, sharedSecret, user, pass)
	seshat.HandleErr(err)

	// close connection to server
	conn.Close()

	// TODO: start up the server part (not concurrently cause the server must be started on both peers before they can do anything)
	// TODO: authenticate the peer over the new server (probably concurrently)
	// TODO: start messaging (concurrently, with channels and selects probably)
	// FIXME: i can't actually do that cause i need two different IPs! => maybe test on IMUNES

	// peerConn, err := hermes.ConnectToPeer(ownClientKey, peerStoredKey, peerIP)
	// seshat.HandleErr(err)

}
