package cerberus

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"
)

// Tests errorless function of the data extraction.
func Test_extractDataNonce(t *testing.T) {
	for i := 0; i < 10; i++ {
		uname := []byte("cerberus")
		nonce := make([]byte, 32)
		rand.Read(nonce)
		m := append(nonce, uname...)

		d, n, err := extractDataNonce(m, 32)
		if err != nil {
			t.Fatal(err)
		}

		if string(d) != string(uname) {
			t.Fatalf("the data doesn't match: expected %s, got %s",
				string(uname), string(d))
		}

		if string(n) != string(nonce) {
			t.Fatalf("the nonces don't match: expected %s, got %s",
				hex.EncodeToString(nonce), hex.EncodeToString(n))
		}
	}

	for i := 0; i < 10; i++ {
		uname := []byte("harpocratesishere")
		nonce := make([]byte, 64)
		rand.Read(nonce)
		m := append(nonce, uname...)

		d, n, err := extractDataNonce(m, 64)
		if err != nil {
			t.Fatal(err)
		}
		if string(d) != string(uname) {
			t.Fatalf("(64) the data doesn't match: expected %s, got %s",
				string(uname), string(d))
		}

		if string(n) != string(nonce) {
			t.Fatalf("(64) the nonces don't match: expected %s, got %s",
				hex.EncodeToString(nonce), hex.EncodeToString(n))
		}
	}
}

// Tests the data extraction when the nonce lengths are invalid.
func Test_extractDataNonce_invalidNonces(t *testing.T) {
	for i := 20; i < 55; i++ {
		unmae := []byte("testingtest")
		nonce := make([]byte, i)
		rand.Read(nonce)
		m := append(nonce, unmae...)

		_, _, err := extractDataNonce(m, i)
		if i == 32 {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if err == nil {
				t.Fatalf("all nonces with lengths != [32, 64] must raise an error (got %d)", i)
			}
		}
	}
}

// Tests data extraction when the data is of an invalid length (too short).
func Test_extractDataNonce_shortData(t *testing.T) {
	for i := 20; i < 40; i++ {
		m := make([]byte, i)
		rand.Read(m)

		_, _, err := extractDataNonce(m, 32)
		if i < 32 {
			if err == nil {
				t.Fatalf("short data should raise an error (got datalen %d)", len(m))
			}
		} else {
			if err != nil {
				t.Fatalf("data of the correct length shouldn't return an error (got datalen %d)", len(m))
			}
		}
	}
}

// Tests the normal function of the getServerSig() function.
func Test_getServerSig(t *testing.T) {
	for i := 0; i < 100; i++ {
		cProof := make([]byte, 32)
		rand.Read(cProof)
		sKey := make([]byte, 32)
		rand.Read(sKey)

		sig, err := getServerSig(cProof, sKey)
		if err != nil {
			t.Fatal(err)
		}

		check := hmac.New(sha256.New, cProof)
		_, err = check.Write(sKey)
		if err != nil {
			t.Fatal(err)
		}

		if !hmac.Equal(check.Sum(nil), sig) {
			t.Fatalf("the two macs are different: expected %s == %s",
				hex.EncodeToString(check.Sum(nil)), hex.EncodeToString(sig))
		}
	}
}
