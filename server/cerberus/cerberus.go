// The cerberus package (just as the three-headed dog whose name it has) is responsible for authentication.
package cerberus

import (
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func DoMutualAuth(conn net.Conn, sharedKey []byte) (anubis.Cipher, error) {
	cipher, err := anubis.NewCipher(sharedKey)
	if err != nil {
		return anubis.Cipher{}, err
	}

	err = scram(conn, cipher)
	if err != nil {
		return anubis.Cipher{}, err
	}

	return cipher, nil
}
