package main

import (
	"bytes"
	"fmt"
	"syscall"

	"github.com/http-server/m/tcp"
)

func main() {
	fd, err := syscall.Socket(17, 3, 0x0300) // AF_PACKET, SOCK_RAW, ETH_P_ALL
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	stack := tcp.NewStack(fd)
	listener := stack.Listen(80)

	fmt.Println("HTTP server listening on port 80...")

	for {
		conn := listener.Accept()
		fmt.Println("Connection accepted")
		go handleConn(conn)
	}
}

func handleConn(conn *tcp.TCPConnection) {
	defer conn.Close()

	// Read until end-of-headers. Ignores request body (fine for GET).
	var req []byte
	buf := make([]byte, 1024)
	for !bytes.Contains(req, []byte("\r\n\r\n")) {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		req = append(req, buf[:n]...)
	}
	fmt.Printf("Request:\n%s\n", req)

	body := "Hello\n"
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		len(body), body,
	)
	conn.Write([]byte(resp))
}
