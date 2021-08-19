// Package  implements functionality related to the TCP connection between client and server (seeing as Hermes is the god of travelers and boundaries (among other things)).
package hermes

import (
	"crypto/elliptic"
	"crypto/sha512"
	"net"

	"github.com/mowzhja/harpocrates/client/seshat"
)

const PEER_PORT = "55555"

// Establishes the P2P connection.
// Return the established connection and an error.
// func ConnectToPeer(ownClientKey, peerStoredKey []byte, peerIP string) (net.Conn, error) {
// 	peerAddress := peerIP + PEER_PORT
// 	tempConn, err := net.Dial("tcp", peerAddress)
// }

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
