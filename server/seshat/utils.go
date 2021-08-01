package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
)

func handleErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func xor(x, y []byte) ([]byte, error) {
	if subtle.ConstantTimeCompare(x, y) == 1 {
		r := make([]byte, len(x))

		for idx, bx := range x {
			r = append(r, bx^y[idx])
		}

		return r, nil
	}

	return nil, errors.New("byte strings should have the same length to XOR")
}

// Merges a bunch of chunks (of type []byte)
func mergeChunks(chunks ...[]byte) []byte {
	slab := []byte{}
	for _, chunk := range chunks {
		slab = append(slab, chunk...)
	}

	return slab
}
