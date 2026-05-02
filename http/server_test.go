package http

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// rwPair joins a Reader and a Writer into an io.ReadWriter for Serve tests.
type rwPair struct {
	io.Reader
	io.Writer
}

func TestServe_RoutesToHandler(t *testing.T) {
	withFixedClock(t)

	mux := NewServeMux()
	mux.RegisterHandler("/hello", func(req *Request, w *ResponseWriter) {
		w.WriteHeader(200)
		w.Write([]byte("hi"))
	})

	in := strings.NewReader("GET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
	var out bytes.Buffer
	Serve(rwPair{in, &out}, mux)

	got := out.String()
	if !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("status line wrong:\n%s", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\nhi") {
		t.Errorf("body wrong:\n%s", got)
	}
}

func TestServe_404OnUnknownRoute(t *testing.T) {
	withFixedClock(t)

	mux := NewServeMux()
	in := strings.NewReader("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n")
	var out bytes.Buffer
	Serve(rwPair{in, &out}, mux)

	if !strings.HasPrefix(out.String(), "HTTP/1.1 404 Not Found\r\n") {
		t.Errorf("expected 404, got:\n%s", out.String())
	}
}

func TestServe_MalformedRequestGets400(t *testing.T) {
	withFixedClock(t)

	mux := NewServeMux()
	in := strings.NewReader("GET / HTTP/1.1\r\n\r\n") // missing Host
	var out bytes.Buffer
	Serve(rwPair{in, &out}, mux)

	if !strings.HasPrefix(out.String(), "HTTP/1.1 400 Bad Request\r\n") {
		t.Errorf("expected 400, got:\n%s", out.String())
	}
}

func TestServe_HTTP10Gets505(t *testing.T) {
	withFixedClock(t)

	mux := NewServeMux()
	in := strings.NewReader("GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	var out bytes.Buffer
	Serve(rwPair{in, &out}, mux)

	if !strings.HasPrefix(out.String(), "HTTP/1.1 505 HTTP Version Not Supported\r\n") {
		t.Errorf("expected 505, got:\n%s", out.String())
	}
}

func TestServe_EmptyConnQuietClose(t *testing.T) {
	withFixedClock(t)

	mux := NewServeMux()
	in := strings.NewReader("") // peer closed before sending anything
	var out bytes.Buffer
	Serve(rwPair{in, &out}, mux)

	if out.Len() != 0 {
		t.Errorf("expected no response on quiet close, got %d bytes:\n%s",
			out.Len(), out.String())
	}
}

func TestServe_HandlerSeesParsedRequest(t *testing.T) {
	withFixedClock(t)

	var seen *Request
	mux := NewServeMux()
	mux.RegisterHandler("/echo", func(req *Request, w *ResponseWriter) {
		seen = req
		w.Write(req.Body)
	})

	body := "payload"
	raw := "POST /echo HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Content-Length: 7\r\n" +
		"\r\n" + body
	var out bytes.Buffer
	Serve(rwPair{strings.NewReader(raw), &out}, NewServeMux())

	// Re-run with a registered handler — first call had a fresh empty mux.
	out.Reset()
	Serve(rwPair{strings.NewReader(raw), &out}, mux)

	if seen == nil {
		t.Fatal("handler not invoked")
	}
	if seen.Method != "POST" {
		t.Errorf("Method = %q", seen.Method)
	}
	if string(seen.Body) != body {
		t.Errorf("Body = %q", seen.Body)
	}
	if !strings.HasSuffix(out.String(), "\r\n\r\n"+body) {
		t.Errorf("response body wrong:\n%s", out.String())
	}
}
