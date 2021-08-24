package cerberus

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/mowzhja/harpocrates/client/seshat"
	"golang.org/x/crypto/argon2"
)

// Computes the parameters used for SCRAM given the password and the salt.
// Returns the auth message, the server key and an error if anything goes wrong.
func computeParams(passwd, salt, nonce []byte) ([]byte, []byte, []byte, error) {
	if len(passwd) == 0 || len(salt) == 0 {
		return nil, nil, nil, errors.New("password, salt or both are empty")
	}
	if len(nonce) != 64 {
		return nil, nil, nil, errors.New("the nonce must be 64 bytes long")
	}

	saltedPasswd := argon2.Key(passwd, salt, 1, 2_000_000, 2, 32)

	clientKey := hmac.New(sha256.New, saltedPasswd)
	clientKey.Write([]byte("Client Key"))
	servKey := hmac.New(sha256.New, saltedPasswd)
	servKey.Write([]byte("Server Key"))
	storedKey := sha256.Sum256(clientKey.Sum(nil))

	clientSignature := hmac.New(sha256.New, storedKey[:])
	clientSignature.Write(nonce)

	clientProof, err := seshat.XOR(clientSignature.Sum(nil), clientKey.Sum(nil))
	if err != nil {
		return nil, nil, nil, err
	}
	authMessage := seshat.MergeChunks(nonce, clientProof)

	return authMessage, servKey.Sum(nil), clientKey.Sum(nil), nil
}

// Computes the server signature client-side.
// Returns the server signature and an error.
func getServerSignature(authMessage, servKey []byte) ([]byte, error) {
	serverSignature := hmac.New(sha256.New, servKey)
	n, err := serverSignature.Write(authMessage)
	if err != nil {
		return nil, err
	} else if n < 32 {
		return nil, errors.New("the signature should be 32 bytes (256 bits) long")
	}

	return serverSignature.Sum(nil), nil
}
