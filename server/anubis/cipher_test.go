package anubis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

// Tests the creation of a Cipher.
func Test_NewCipher(t *testing.T) {
	nonces := make(map[string]bool) // used to check for nonce uniqueness

	N := 40
	for i := 0; i < N; i++ {
		key := make([]byte, BYTE_SEC)
		rand.Read(key)

		c, err := NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		if string(c.key) != string(key) {
			t.Fatalf("they key fed to the function is not the same as the one used for the Cipher: expected %s, got %s",
				hex.EncodeToString(key), hex.EncodeToString(c.key))
		}

		if len(c.nonce) != BYTE_SEC {
			t.Fatal("the nonce should be 32 bytes long")
		}
		nonces[string(c.nonce)] = true

		aes, _ := aes.NewCipher(key)
		AEAD, _ := cipher.NewGCM(aes)
		if reflect.TypeOf(c.aead) != reflect.TypeOf(AEAD) {
			t.Fatalf("Cipher.aead is not of the correct type: expected %s, got %s",
				reflect.TypeOf(AEAD), reflect.TypeOf(c.aead))
		}
	}

	if len(nonces) < 40 {
		t.Fatal("NewCipher() produced a duplicate nonce")
	}
}

// Tests encryption and decryption.
func Test_encryptDecrypt(t *testing.T) {
	for i := 0; i < 100; i++ {
		plaintext := []byte("testingthetestingtest")
		key := make([]byte, BYTE_SEC)
		rand.Read(key)

		c, err := NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		if p, err := c.decrypt(c.encrypt(plaintext)); err == nil {
			if string(p) != string(plaintext) {
				t.Fatalf("the encryption and decryption are incorrect: expected %s, got %s", string(plaintext), string(p))
			}
		} else {
			t.Fatal(err)
		}
	}
}
