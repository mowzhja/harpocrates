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

// Wrapper for convenience and readability
func returnErr(err error) error {
	if err != nil {
		return err
	}

	return nil
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
