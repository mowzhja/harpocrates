// The cerberus package (just as the three-headed dog whose name it has) is responsible for authentication.
package cerberus

import (
	"net"

	"github.com/mowzhja/harpocrates/client/anubis"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func DoMutualAuth(conn net.Conn, sharedKey, uname, passwd []byte) error {
	cipher, err := anubis.NewCipher(sharedKey)
	if err != nil {
		return nil
	}

	err = scram(conn, cipher, uname, passwd)
	if err != nil {
		return nil
	}

	return nil
}
