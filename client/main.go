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

	// FIXME: maybe test on IMUNES

	// TODO: this should technically be a goroutine
	// => the data passed between the peers is not necessarily as neat and orderly as it was between client and server
	readConn, writeConn, err := hermes.ConnectToPeer(ownClientKey, peerStoredKey, peerIP)
	seshat.HandleErr(err)

	readc := make(chan string)
	writec := make(chan string)
	for {
		// both functions in hermes, obvs
		go hermes.PeerRead(readConn, readc)
		go hermes.PeerWrite(writeConn, writec)

		select {
		case readMsg := <-readc:
			// read from peer
			printOnScreen(readMsg)
		case writeMsg := <-writec:
			// wrote to peer
			writeToPeer(writeMsg)
		}
	}
}
