// The cerberus package (just as the three-headed dog whose name it has) is responsible for authentication.
package cerberus

import (
	"crypto/rand"
	"net"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/coeus"
)

// Connects the two peers with one another, thus ending the server's function.
// Returns an error if anything went wrong.
func ConnectPeers(conn net.Conn, sharedKey []byte) error {
	cipher, err := doMutualAuth(conn, sharedKey)
	if err != nil {
		return err
	}

	peer_uname, _, err := checkRead(conn, cipher)
	if err != nil {
		return err
	}

	// check for existence
	_, _, _, err = coeus.GetCorrespondingInfo(string(peer_uname))
	if err != nil {
		return err
	}

	nonce := make([]byte, anubis.BYTE_SEC)
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	_, err = fullWrite(conn, nonce, cipher)
	if err != nil {
		return err
	}

	return nil
}
