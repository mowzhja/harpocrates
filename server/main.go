package main

import (
	"flag"
	"net"
	"strings"
)

const PACKET_SIZE = 1000

func main() {
	var sb strings.Builder

	ipAddr := flag.String("addr", "127.0.0.1", "ip address of the server")
	port := flag.String("port", "9001", "server port")

	sb.WriteString(*ipAddr)
	sb.WriteString(":")
	sb.WriteString(*port)

	addr, err := net.ResolveTCPAddr("tcp", sb.String())
	handleErr(err)

	listener, err := net.ListenTCP("tcp", addr)
	handleErr(err)

	for {
		conn, err := listener.Accept()
		handleErr(err)

		// goroutine
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) error {
	defer conn.Close()

	sharedKey, err := doECDHE(conn)
	handleErr(err)

	err = doMutualAuth(conn, sharedKey)
	handleErr(err)

	return nil
}
