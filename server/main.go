package main

import (
	"flag"
	"net"
	"strings"

	"github.com/mowzhja/harpocrates/server/cerberus"
	"github.com/mowzhja/harpocrates/server/hermes"
	"github.com/mowzhja/harpocrates/server/seshat"
)

func main() {
	var sb strings.Builder

	ipAddr := flag.String("addr", "127.0.0.1", "ip address of the server")
	port := flag.String("port", "9001", "server port")

	sb.WriteString(*ipAddr)
	sb.WriteString(":")
	sb.WriteString(*port)

	addr, err := net.ResolveTCPAddr("tcp", sb.String())
	seshat.HandleErr(err)

	listener, err := net.ListenTCP("tcp", addr)
	seshat.HandleErr(err)

	for {
		conn, err := listener.Accept()
		seshat.HandleErr(err)

		// goroutine
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) error {
	defer conn.Close()

	sharedKey, err := hermes.DoECDHE(conn)
	seshat.HandleErr(err)

	err = cerberus.DoMutualAuth(conn, sharedKey)
	seshat.HandleErr(err)

	return nil
}
