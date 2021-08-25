package cerberus

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/mowzhja/harpocrates/server/seshat"
	"golang.org/x/crypto/argon2"
)

// Tests normal verification of the various client-side parameters.
func Test_authClient(t *testing.T) {
	passwd := []byte("secretpass")
	salt := make([]byte, 32)
	rand.Read(salt)

	for i := 0; i < 2; i++ {
		// made up parameters for SCRAM
		nonce := make([]byte, 64) // client-server nonce
		rand.Read(nonce)
		saltedPassword := argon2.Key(passwd, salt, 1, 2_000_000, 2, 32)

		clientKey := hmac.New(sha256.New, saltedPassword)
		clientKey.Write([]byte("Client Key"))
		storedKey := sha256.Sum256(clientKey.Sum(nil))
		clientSig := hmac.New(sha256.New, storedKey[:])
		clientSig.Write(nonce)

		clientProof, err := seshat.XOR(clientSig.Sum(nil), clientKey.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}

		err = authClient(clientProof, nonce, storedKey[:])
		if err != nil {
			t.Fatal(err)
		}
	}
}
