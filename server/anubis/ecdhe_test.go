package anubis

import (
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

// Tests whether the generated keys are all unique (for N keys).
func Test_generateKeys_Uniqueness(t *testing.T) {
	E := elliptic.P521()
	// Emulate a HashSet
	privs := make(map[string]interface{})
	pubs := make(map[string]interface{})

	N := 100
	for i := 0; i < N; i++ {
		priv, pub, err := generateKeys(E)
		if err != nil {
			t.Fatal(err)
		}

		// All keys withing a hash map must be unique...
		privs[string(priv)] = struct{}{}
		pubs[string(pub)] = struct{}{}
	}

	//...thus the len(map) must equal N
	if len(privs) < N || len(pubs) < N {
		t.Fatalf("generated duplicate keys (expected %d unique ones, got %d)",
			N, len(privs))
	}
}

// Tests that only P-521 is accepted as a valid curve.
func Test_calculateSharedSecret_Curves(t *testing.T) {
	expected := "only the NIST P-521 curve is accepted"

	_, err := calculateSharedSecret(elliptic.P224(), nil, nil)
	if err.Error() != expected {
		t.Fatal("p224 should not be accepted as a valid curve")
	}

	_, err = calculateSharedSecret(elliptic.P256(), nil, nil)
	if err.Error() != expected {
		t.Fatal("p256 should not be accepted as a valid curve")
	}

	_, err = calculateSharedSecret(elliptic.P384(), nil, nil)
	if err.Error() != expected {
		t.Fatal("p384 should not be accepted as a valid curve")
	}

	_, err = calculateSharedSecret(elliptic.P521(), nil, nil)
	if err.Error() == expected {
		t.Fatal(err)
	}
}

// Tests the validity of some simulated exchanges (further test coverage should be obtained through integration tests).
func Test_calculateSharedSecret_Exchanges(t *testing.T) {
	E := elliptic.P521()

	N := 100
	for i := 0; i < N; i++ {
		sPriv, sPub, err := generateKeys(E) // server side
		if err != nil {
			t.Fatal(err)
		}
		cPriv, cPub, err := generateKeys(E) // client side
		if err != nil {
			t.Fatal(err)
		}

		sShared, err := calculateSharedSecret(E, cPub, sPriv)
		if err != nil {
			t.Fatal(err)
		}
		cShared, err := calculateSharedSecret(E, sPub, cPriv)
		if err != nil {
			t.Fatal(err)
		}

		if string(cShared) != string(sShared) {
			t.Fatalf("the shared secrets are not the same(%s != %s)",
				hex.EncodeToString(cShared), hex.EncodeToString(sShared))
		}
	}
}
