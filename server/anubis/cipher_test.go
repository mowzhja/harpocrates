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

// Tests getting the nonce with the Nonce() method.
func Test_Nonce(t *testing.T) {
	for i := 0; i < 50; i++ {
		key := make([]byte, 32)
		rand.Read(key)

		cipher, err := NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		if string(cipher.nonce) != string(cipher.Nonce()) {
			t.Fatalf("the two nonces should be equal: expected %s, got %s",
				hex.EncodeToString(cipher.nonce), hex.EncodeToString(cipher.Nonce()))
		}
	}
}

// Tests the updating of the nonce through the UpdateNonce() method.
func Test_UpdateNonce(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	for i := 20; i < 70; i++ {
		nonce := make([]byte, i)
		err := cipher.UpdateNonce(nonce)
		if err != nil {
			t.Fatal(err)
		}

		if string(nonce) != string(cipher.nonce) {
			t.Fatalf("the two nonces should be equal: expected %s, got %s",
				hex.EncodeToString(nonce), hex.EncodeToString(cipher.nonce))
		}
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

		if p, err := c.Decrypt(c.Encrypt(plaintext)); err == nil {
			if string(p) != string(plaintext) {
				t.Fatalf("the encryption and decryption are incorrect: expected %s, got %s", string(plaintext), string(p))
			}
		} else {
			t.Fatal(err)
		}
	}
}
