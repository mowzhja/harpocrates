package anubis

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
)

// Generates the private/public key pair for ECDH.
func generateKeys(E elliptic.Curve) ([]byte, []byte, error) {
	privKey, x, y, err := elliptic.GenerateKey(E, rand.Reader)
	if !E.IsOnCurve(x, y) {
		return nil, nil, errors.New("the generated parameters are not on the curve")
	}

	pubKey := elliptic.Marshal(E, x, y)

	return privKey, pubKey, err
}

// Calculates the shared secret given our private key and the public key of the other party.
func calculateSharedSecret(E elliptic.Curve, pubKey, privKey []byte) ([]byte, error) {
	if E != elliptic.P521() {
		return nil, errors.New("only the NIST P-521 curve is accepted")
	}

	cx, cy := elliptic.Unmarshal(E, pubKey)
	// Unmarshal() returns (nil, nil) if there were errors: https://golang.google.cn/src/crypto/elliptic/elliptic.go?s=9365:9421#L330
	if cx == nil || cy == nil {
		return nil, errors.New("error unmarshaling the client's public key")
	}

	sx, sy := E.ScalarMult(cx, cy, privKey) // shared (x, y)
	return elliptic.Marshal(E, sx, sy), nil
}
