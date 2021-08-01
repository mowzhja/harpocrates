package hermes

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"net"

	"github.com/mowzhja/harpocrates/server/seshat"
)

// Responsible for the actual ECDHE.
func DoECDHE(conn net.Conn) ([]byte, error) {
	privBytes, x, y, pubBytes, err := generateKeys()
	seshat.HandleErr(err)

	buf := make([]byte, len(pubBytes))

	_, err = conn.Read(buf[:])
	seshat.HandleErr(err)

	sharedSecret, err := calculateSharedSecret(buf, privBytes, x, y)
	seshat.HandleErr(err)

	_, err = conn.Write(pubBytes[:])
	seshat.HandleErr(err)

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
