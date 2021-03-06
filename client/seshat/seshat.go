// Seshat is the ancient goddess of wisdom, knowledge and writing and the "Mistress of the House of Books"
// The package seshat, thus, contains useful functions (a library) for the rest of the project.
package seshat

import (
	"errors"
)

// Error handler for main.
func HandleErr(err error) {
	if err != nil {
		panic(err)
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
// Returns the data, the nonce and an error, in the order specified.
func ExtractDataNonce(cdata []byte, nlen int) ([]byte, []byte, error) {
	if !(nlen == 32 || nlen == 64) {
		return nil, nil, errors.New("nonce must be either 32 or 64 bytes long")
	} else if len(cdata) < nlen {
		return nil, nil, errors.New("data is too short")
	}
	nonce := cdata[:nlen]
	data := cdata[nlen:]

	return data, nonce, nil
}
