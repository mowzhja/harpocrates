package main

import (
	"flag"
	"net"
	"strings"

	"github.com/mowzhja/harpocrates/server/anubis"
	"github.com/mowzhja/harpocrates/server/cerberus"
	"github.com/mowzhja/harpocrates/server/seshat"
)

func main() {
	ip := flag.String("ip", "127.0.0.1", "ip address of the server")
	port := flag.String("port", "9001", "server port")

	var address strings.Builder
	address.WriteString(*ip)
	address.WriteString(":")
	address.WriteString(*port)

	listener, err := net.Listen("tcp", address.String())
	seshat.HandleErr(err)

	for {
		conn, err := listener.Accept()
		seshat.HandleErr(err)

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) error {
	defer conn.Close()

	sharedKey, err := anubis.DoECDHE(conn)
	seshat.HandleErr(err)

	err = cerberus.ConnectPeers(conn, sharedKey)
	seshat.HandleErr(err)

	return nil
}
