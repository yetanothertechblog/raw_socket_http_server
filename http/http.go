package http

import "strings"

type Request struct {
	Method  string
	Path    string
	Version string
	// Headers keys are stored lower-cased. Duplicate occurrences of the same
	// header name are joined with ", " per RFC 7230 §3.2.2.
	Headers map[string]string
	Body    []byte
}

type ResponseWriter struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	w.Body = append(w.Body, data...)
	return len(data), nil
}

func (w *ResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
}

type HandlerFunc func(*Request, *ResponseWriter)

// ServeMux is a tiny HTTP request router.
//
// Patterns NOT ending in "/" are exact-match: they match only when req.Path
// equals the pattern character-for-character. Patterns ending in "/" are
// prefix-match: they match any req.Path that has that pattern as a prefix.
// When both could match, exact wins; among multiple prefix matches, the
// longest one wins. Matches stdlib net/http.ServeMux semantics.
//
// Registering "/" therefore creates a catch-all (every path begins with "/"),
// which is usually not what you want unless the handler self-checks
// req.Path == "/".
type ServeMux struct {
	exact  map[string]HandlerFunc
	prefix map[string]HandlerFunc
}

func NewServeMux() *ServeMux {
	return &ServeMux{
		exact:  make(map[string]HandlerFunc),
		prefix: make(map[string]HandlerFunc),
	}
}

func (mux *ServeMux) RegisterHandler(pattern string, handlerFunc HandlerFunc) {
	if mux.exact == nil {
		mux.exact = make(map[string]HandlerFunc)
	}
	if mux.prefix == nil {
		mux.prefix = make(map[string]HandlerFunc)
	}
	if strings.HasSuffix(pattern, "/") {
		mux.prefix[pattern] = handlerFunc
	} else {
		mux.exact[pattern] = handlerFunc
	}
}

// match returns the handler for path: exact first, then longest matching
// prefix. Returns nil if nothing matches.
func (mux *ServeMux) match(path string) HandlerFunc {
	if h, ok := mux.exact[path]; ok {
		return h
	}
	var best HandlerFunc
	bestLen := -1
	for pat, h := range mux.prefix {
		if len(pat) > bestLen && strings.HasPrefix(path, pat) {
			best = h
			bestLen = len(pat)
		}
	}
	return best
}

func (mux *ServeMux) Handle(req *Request) *ResponseWriter {
	w := &ResponseWriter{
		StatusCode: 200,
		Headers:    make(map[string]string),
	}
	handler := mux.match(req.Path)
	if handler == nil {
		w.StatusCode = 404
		w.Write([]byte("404 Not Found\n"))
		return w
	}
	handler(req, w)
	return w
}

var statusTexts = map[int]string{
	200: "OK",
	201: "Created",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	304: "Not Modified",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	411: "Length Required",
	413: "Payload Too Large",
	431: "Request Header Fields Too Large",
	500: "Internal Server Error",
	501: "Not Implemented",
	505: "HTTP Version Not Supported",
}
