package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/mowzhja/harpocrates/server/cerberus"
	"github.com/mowzhja/harpocrates/server/hermes"
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

	fmt.Println("[+] Started listener at", address.String())

	for {
		conn, err := listener.Accept()
		seshat.HandleErr(err)

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	sharedKey, err := hermes.DoECDHE(conn)
	if err != nil {
		conn.Close()
		return
	}

	_, err = cerberus.DoMutualAuth(conn, sharedKey)
	if err != nil {
		conn.Close()
		return
	}

	conn.Close()

	// err = hermes.ConnectPeers(conn, cipher)
	// seshat.HandleErr(err)
}
