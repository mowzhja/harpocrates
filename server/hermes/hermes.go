// Package hermes implements functionality related to the TCP connection between client and server (seeing as Hermes is the god of travelers and boundaries (among other things)).
package hermes

import (
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/coeus"
	"github.com/mowzhja/harpocrates/server/seshat"
)

// Connects the two peers with one another, thus ending the server's function.
// Returns an error if anything went wrong.
func ConnectPeers(conn net.Conn, cipher anubis.Cipher) error {
	fmt.Println("connecting peers")
	peer_uname, _, err := FullRead(conn, cipher)
	if err != nil {
		return err
	}
	fmt.Println("info on", string(peer_uname))

	// check for existence
	_, peerStoredKey, _, err := coeus.GetCorrespondingInfo(string(peer_uname))
	if err != nil {
		return err
	}
	fmt.Println("here")

	_, err = FullWrite(conn, peerStoredKey, cipher)
	if err != nil {
		return err
	}

	return nil
}

// Responsible for ECDHE.
func DoECDHE(conn net.Conn) ([]byte, error) {
	E := elliptic.P521()

	privKey, pubKey, err := generateKeys(E)
	seshat.HandleErr(err)

	clientPub, _, err := Read(conn)
	seshat.HandleErr(err)

	sharedSecret, err := calculateSharedSecret(E, clientPub, privKey)
	seshat.HandleErr(err)

	_, err = Write(conn, pubKey)
	seshat.HandleErr(err)

	sharedKey := sha512.Sum512_256(sharedSecret)

	return sharedKey[:], nil
}
