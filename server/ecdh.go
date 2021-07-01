package crypto_module

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// Generates the private/public key pair for ECDH.
func generateKeys() ([]byte, *big.Int, *big.Int, []byte, error) {
	E := elliptic.P521()
	privKey, x, y, err := elliptic.GenerateKey(E, rand.Reader)
	pubKey := elliptic.Marshal(E, x, y)

	return privKey, x, y, pubKey, err
}

// Calculates the shared secret given the private key and public key of other party.
func calculateSecret(pubBytes, privBytes []byte, x, y *big.Int) ([]byte, error) {
	E := elliptic.P521()
	cx, cy := elliptic.Unmarshal(E, pubBytes) // client x, y

	sx, sy := E.ScalarMult(cx, cy, privBytes) // shared x, y

	return elliptic.Marshal(E, sx, sy), nil
}
