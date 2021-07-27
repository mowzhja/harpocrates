package main

import (
	"crypto/aes"
	"net"
)

func doMutualAuth(conn net.Conn, sharedKey []byte) error {
	cipher, err := aes.NewCipher(sharedKey)
	handleErr(err)

	return nil
}
