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
	E := elliptic.P521()

	privKey, pubKey, x, y, err := generateKeys(E)
	seshat.HandleErr(err)

	buf := make([]byte, len(pubKey))

	_, err = conn.Read(buf[:])
	seshat.HandleErr(err)

	sharedSecret, err := calculateSharedSecret(E, buf, privKey, x, y)
	seshat.HandleErr(err)

	_, err = conn.Write(pubKey[:])
	seshat.HandleErr(err)

	sharedKey := sha512.Sum512_256(sharedSecret)

	return sharedKey[:], nil
}

// Generates the private/public key pair for ECDH.
func generateKeys(E elliptic.Curve) ([]byte, []byte, *big.Int, *big.Int, error) {
	privKey, x, y, err := elliptic.GenerateKey(E, rand.Reader)
	pubKey := elliptic.Marshal(E, x, y)

	return privKey, pubKey, x, y, err
}

// Calculates the shared secret given the private key and public key of the other party.
func calculateSharedSecret(E elliptic.Curve, pubKey, privKey []byte, x, y *big.Int) ([]byte, error) {
	cx, cy := elliptic.Unmarshal(E, pubKey) // client x, y
	fmt.Println(pubKey)
	sx, sy := E.ScalarMult(cx, cy, privKey) // shared x, y

	return elliptic.Marshal(E, sx, sy), nil
}
