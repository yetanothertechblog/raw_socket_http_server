package http

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	maxRequestLine = 8 * 1024
	maxHeaderLine  = 8 * 1024
	maxHeaders     = 100
	maxBodySize    = 1 << 20 // 1 MiB
)

// Parser errors. These are intentionally distinct so the caller can map each
// to the right HTTP status code (400 / 411 / 413 / 505) before sending a
// response. I/O errors (io.EOF, io.ErrUnexpectedEOF, etc.) propagate as-is.
var (
	ErrMalformed           = errors.New("http: malformed request")
	ErrLengthRequired      = errors.New("http: length required")
	ErrPayloadTooLarge     = errors.New("http: payload too large")
	ErrVersionNotSupported = errors.New("http: version not supported")
	ErrTooManyHeaders      = errors.New("http: too many headers")
)

// ReadRequest parses a single HTTP/1.1 request from r. It reads the request
// line, header block, and (if Content-Length is present) the body. The reader
// is wrapped in a bufio.Reader internally; bytes past the body are buffered
// but unused, so for now ReadRequest is intended for one request per call.
func ReadRequest(r io.Reader) (*Request, error) {
	br := bufio.NewReader(r)

	line, err := readLine(br, maxRequestLine)
	if err != nil {
		return nil, err
	}
	method, path, version, ok := parseRequestLine(line)
	if !ok {
		return nil, ErrMalformed
	}
	if version != "HTTP/1.1" {
		return nil, ErrVersionNotSupported
	}

	req := &Request{
		Method:  method,
		Path:    path,
		Version: version,
		Headers: make(map[string]string),
	}

	for i := 0; ; i++ {
		if i >= maxHeaders {
			return nil, ErrTooManyHeaders
		}
		line, err := readLine(br, maxHeaderLine)
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		// RFC 7230 §3.2.4: reject obs-fold (line continuation).
		if line[0] == ' ' || line[0] == '\t' {
			return nil, ErrMalformed
		}
		name, value, ok := parseHeader(line)
		if !ok {
			return nil, ErrMalformed
		}
		name = strings.ToLower(name)
		if existing, dup := req.Headers[name]; dup {
			req.Headers[name] = existing + ", " + value
		} else {
			req.Headers[name] = value
		}
	}

	// HTTP/1.1 requires Host (RFC 7230 §5.4).
	if _, ok := req.Headers["host"]; !ok {
		return nil, ErrMalformed
	}

	if cl, hasCL := req.Headers["content-length"]; hasCL {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			return nil, ErrMalformed
		}
		if n > maxBodySize {
			return nil, ErrPayloadTooLarge
		}
		req.Body = make([]byte, n)
		if _, err := io.ReadFull(br, req.Body); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	} else if methodRequiresLength(method) {
		return nil, ErrLengthRequired
	}

	return req, nil
}

// readLine reads up to and including a \n, returns the line without trailing
// CR/LF. Returns ErrMalformed if the line exceeds max bytes.
func readLine(br *bufio.Reader, max int) (string, error) {
	var buf []byte
	for {
		if len(buf) >= max {
			return "", ErrMalformed
		}
		b, err := br.ReadByte()
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
		if b == '\n' {
			break
		}
		buf = append(buf, b)
	}
	if n := len(buf); n > 0 && buf[n-1] == '\r' {
		buf = buf[:n-1]
	}
	return string(buf), nil
}

func parseRequestLine(line string) (method, path, version string, ok bool) {
	// SplitN on the first two spaces. The path itself must not contain spaces
	// in origin-form, so a third space would be malformed.
	first := strings.IndexByte(line, ' ')
	if first <= 0 {
		return "", "", "", false
	}
	last := strings.LastIndexByte(line, ' ')
	if last == first {
		return "", "", "", false
	}
	method = line[:first]
	path = line[first+1 : last]
	version = line[last+1:]
	if !isValidToken(method) {
		return "", "", "", false
	}
	if path == "" || path[0] != '/' {
		return "", "", "", false
	}
	if strings.ContainsAny(path, " \t") {
		return "", "", "", false
	}
	if !strings.HasPrefix(version, "HTTP/") {
		return "", "", "", false
	}
	return method, path, version, true
}

func parseHeader(line string) (name, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	name = line[:i]
	if !isValidToken(name) {
		return "", "", false
	}
	// RFC 7230 §3.2.4: optional whitespace around field-value, trimmed.
	value = strings.Trim(line[i+1:], " \t")
	return name, value, true
}

// isValidToken reports whether s is a non-empty RFC 7230 token (used for
// method names and header field names).
func isValidToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	return false
}

// methodRequiresLength reports whether a missing Content-Length on this method
// is a 411-worthy error. GET / HEAD / DELETE / OPTIONS bodies are unusual; we
// require explicit framing on the methods that conventionally carry a body.
func methodRequiresLength(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}
