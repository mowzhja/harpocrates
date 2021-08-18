// Seshat is the ancient goddess of wisdom, knowledge and writing and the "Mistress of the House of Books"
// The package seshat, thus, contains useful functions (a library) for the rest of the project.
package seshat

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
)

// Error handler for main.
func HandleErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal error: %s", err.Error())
		os.Exit(1)
	}
}

// Performs bitwise xor for two bytestrings of the same length.
// Returns the resulting bytestring and a nil error if successful, else a nil bytestring and an error.
func XOR(x, y []byte) ([]byte, error) {
	if len(x) == len(y) {
		r := make([]byte, len(x))

		for i := range x {
			r[i] = x[i] ^ y[i]
		}

		return r, nil
	}

	return nil, errors.New("byte strings should have the same length to XOR")
}

// Merges a bunch of chunks (of type []byte).
// Returns the slab resulting from the merger.
func MergeChunks(chunks ...[]byte) []byte {
	slab := []byte{}

	for _, chunk := range chunks {
		slab = append(slab, chunk...)
	}

	return slab
}

// For convenience, extract the nonce and the data contained in a client message.
// Returns the data, the nonce and an error (nil if all good), in the order specified.
func ExtractDataNonce(cdata []byte, nlen int) ([]byte, []byte, error) {
	if !(nlen == 32 || nlen == 64) {
		return nil, nil, errors.New("nonce must be either 32 or 64 bytes long")
	} else if len(cdata) < nlen {
		return nil, nil, errors.New("data is too short")
	}
	nonce := cdata[:nlen]
	rest := cdata[nlen:]

	return rest, nonce, nil
}

// Computes server signature given client proof and server key.
// Returns the server signature and an error (nil if everything is good).
func GetServerSignature(authMessage, servKey []byte) ([]byte, error) {
	serverSignature := hmac.New(sha256.New, servKey)
	n, err := serverSignature.Write(authMessage)
	if err != nil {
		return nil, err
	} else if n < 32 {
		return nil, errors.New("the signature should be 32 bytes (256 bits) long")
	}

	return serverSignature.Sum(nil), nil
}
