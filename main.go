package main

import (
	"fmt"
	"syscall"

	"github.com/http-server/m/http"
	"github.com/http-server/m/orders"
	"github.com/http-server/m/tcp"
	"github.com/http-server/m/tls"
)

func main() {
	fd, err := syscall.Socket(17, 3, 0x0300) // AF_PACKET, SOCK_RAW, ETH_P_ALL
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	identity, err := tls.NewServerIdentity()
	if err != nil {
		panic(fmt.Errorf("generating server identity: %w", err))
	}

	store, err := orders.NewStore(":memory:")
	if err != nil {
		panic(fmt.Errorf("opening order store: %w", err))
	}
	defer store.Close()

	stack := tcp.NewStack(fd)
	listener := stack.Listen(443)

	mux := http.NewServeMux()
	orders.Register(mux, store)
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
		w.Write([]byte("Hello over our own TLS!\n"))
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

	fmt.Println("HTTPS server listening on port 443...")

	for {
		conn := listener.Accept()
		fmt.Println("Connection accepted")
		go func(c *tcp.TCPConnection) {
			defer c.Close()
			tlsConn := tls.Server(c, identity)
			if err := tlsConn.Handshake(); err != nil {
				fmt.Printf("TLS handshake failed: %v\n", err)
				return
			}
			http.Serve(tlsConn, mux)
		}(conn)
	}
}
