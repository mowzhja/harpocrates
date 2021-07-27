package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"net"
)

// Responsible for the actual ECDHE.
func doECDHE(conn net.Conn) ([]byte, error) {
	privBytes, x, y, pubBytes, err := generateKeys()
	handleErr(err)

	buf := make([]byte, len(pubBytes))

	_, err = conn.Read(buf[:])
	handleErr(err)

	sharedSecret, err := calculateSharedSecret(buf, privBytes, x, y)
	handleErr(err)

	_, err = conn.Write(pubBytes[:])
	handleErr(err)

	sharedKey := sha512.Sum512_256(sharedSecret)

	return sharedKey[:], nil
}

// Generates the private/public key pair for ECDH.
func generateKeys() ([]byte, *big.Int, *big.Int, []byte, error) {
	E := elliptic.P521()
	privKey, x, y, err := elliptic.GenerateKey(E, rand.Reader)
	pubKey := elliptic.Marshal(E, x, y)

	return privKey, x, y, pubKey, err
}

// Calculates the shared secret given the private key and public key of the other party.
func calculateSharedSecret(pubBytes, privBytes []byte, x, y *big.Int) ([]byte, error) {
	E := elliptic.P521()

	cx, cy := elliptic.Unmarshal(E, pubBytes) // client x, y
	fmt.Println(pubBytes)
	sx, sy := E.ScalarMult(cx, cy, privBytes[:]) // shared x, y

	return elliptic.Marshal(E, sx, sy), nil
}
