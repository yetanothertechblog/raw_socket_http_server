package main

import (
	"fmt"
	"syscall"

	"github.com/http-server/m/http"
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

	mux := http.NewServeMux()
	// "/" is registered as a prefix pattern (trailing slash → catch-all).
	// We self-check req.Path so unknown paths still 404 instead of getting
	// the index page.
	mux.RegisterHandler("/", func(req *http.Request, w *http.ResponseWriter) {
		if req.Path != "/" {
			w.WriteHeader(404)
			w.Write([]byte("404 Not Found\n"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("Hello\n"))
	})
	mux.RegisterHandler("/healthz", func(req *http.Request, w *http.ResponseWriter) {
		w.WriteHeader(200)
		w.Write([]byte("ok\n"))
	})
	// Prefix demo: every /echo/<x> returns <x>.
	mux.RegisterHandler("/echo/", func(req *http.Request, w *http.ResponseWriter) {
		w.WriteHeader(200)
		w.Write([]byte(req.Path[len("/echo/"):] + "\n"))
	})

	fmt.Println("HTTP server listening on port 80...")

	for {
		conn := listener.Accept()
		fmt.Println("Connection accepted")
		go func(c *tcp.TCPConnection) {
			defer c.Close()
			http.Serve(c, mux)
		}(conn)
	}
}
