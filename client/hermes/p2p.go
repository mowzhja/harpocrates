package hermes

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"

	"github.com/multiformats/go-multiaddr"
)

func peerRead(rw *bufio.ReadWriter) {
	for {
		str, _ := rw.ReadString('\n')
		if str == "" {
			return
		}

		if str != "\n" {
			fmt.Printf("%s\n", str)
		}
	}
}

func peerWrite(rw *bufio.ReadWriter) {
	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			return
		}

		rw.WriteString(fmt.Sprintf("%s\n", sendData))
		rw.Flush()
	}
}

func makeHost(ctx context.Context, ip string, port int) (host.Host, error) {
	srcAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", ip, port))

	// libp2p.New() constructs a new libp2p Host.
	// Other options can be added here.
	return libp2p.New(
		ctx,
		libp2p.ListenAddrs(srcAddr),
	)
}

func startPeerAndConnect(ctx context.Context, host host.Host, peerAddr string) (*bufio.ReadWriter, error) {
	maddr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return nil, err
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, err
	}

	// Add the destination's peer multiaddress in the peerstore.
	host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// Start a stream with the destination.
	s, err := host.NewStream(context.Background(), info.ID, "/harpocrates/1.0.0")
	if err != nil {
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	return rw, nil
}
