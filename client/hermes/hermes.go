// Package  implements functionality related to the TCP connection between client and server (seeing as Hermes is the god of travelers and boundaries (among other things)).
package hermes

import (
	"context"
	"crypto/elliptic"
	"crypto/sha512"
	"net"

	"github.com/mowzhja/harpocrates/client/seshat"
)

// Establishes and manages the P2P connection.
func PeerToPeer(ownClientKey, peerStoredKey []byte, peerAddr string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host, err := makeHost(ctx, "127.0.0.1", 55555)
	seshat.HandleErr(err)

	rw, err := startPeerAndConnect(ctx, host, peerAddr)
	seshat.HandleErr(err)

	// Create a thread to read and write data.
	go peerWrite(rw)
	go peerRead(rw)

	// Wait forever
	select {}
}

// Responsible for the actual ECDHE.
// Returns the shared secret (the key for symmetric crypto) and an error if anything goes wrong.
func DoECDHE(conn net.Conn) ([]byte, error) {
	E := elliptic.P521()

	privKey, pubKey, err := generateKeys(E)
	seshat.HandleErr(err)

	_, err = Write(conn, pubKey)
	seshat.HandleErr(err)

	serverPub, _, err := Read(conn)
	seshat.HandleErr(err)

	sharedSecret, err := calculateSharedSecret(E, serverPub, privKey)
	seshat.HandleErr(err)

	sharedKey := sha512.Sum512_256(sharedSecret)

	return sharedKey[:], nil
}
