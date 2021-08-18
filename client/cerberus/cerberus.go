// The cerberus package (just as the three-headed dog whose name it has) is responsible for authentication.
package cerberus

import (
	"net"

	"github.com/mowzhja/harpocrates/client/anubis"
)

// Implements the mutual challenge-response auth between server and clients.
// Assumes the sharedKey is secret (only known to server and client)!
func GetPeerData(conn net.Conn, sharedKey, uname, passwd []byte) ([]byte, []byte, error) {
	cipher, err := anubis.NewCipher(sharedKey)
	if err != nil {
		return nil, nil, err
	}

	ownClientKey, err := scram(conn, cipher, uname, passwd)
	if err != nil {
		return nil, nil, err
	}

	_, err = fullWrite(conn, []byte("bob"), cipher)
	if err != nil {
		return nil, nil, err
	}

	peerStoredKey, _, err := checkRead(conn, cipher)
	if err != nil {
		return nil, nil, err
	}

	return ownClientKey, peerStoredKey, nil
}
