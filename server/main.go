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
	var sb strings.Builder

	ipAddr := flag.String("addr", "127.0.0.1", "ip address of the server")
	port := flag.String("port", "9001", "server port")

	sb.WriteString(*ipAddr)
	sb.WriteString(":")
	sb.WriteString(*port)

	listener, err := net.Listen("tcp", sb.String())
	seshat.HandleErr(err)

	for {
		conn, err := listener.Accept()
		seshat.HandleErr(err)

		// goroutine
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) error {
	sharedKey, err := anubis.DoECDHE(conn)
	seshat.HandleErr(err)

	err = cerberus.DoMutualAuth(conn, sharedKey)
	seshat.HandleErr(err)

	conn.Close()
	return nil
}
