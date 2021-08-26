// built by following along here: https://docs.libp2p.io/tutorials/getting-started/go/
package main

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
)

func main() {
	ctx := context.Background()

	// start a libp2p node with default settings
	node, err := libp2p.New(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Println("[+] Listen addresses:", node.Addrs())

	if err := node.Close(); err != nil {
		panic(err)
	}
}
