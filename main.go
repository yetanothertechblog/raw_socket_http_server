package main

import (
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

	fmt.Println("TCP echo server listening on port 80...")

	for {
		conn := listener.Accept()
		fmt.Println("Connection accepted")
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				// EOF Recieved
				break
			}
			fmt.Printf("Received: %s\n", string(buf[:n]))
			n, err = conn.Write(buf[:n])
			if err != nil {
				fmt.Printf("Sent %d bytes : %s", n, buf[:n])
			}
		}

		conn.Close()
	}
}
