package http

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

const (
	serverName     = "rawhttp"
	httpDateFormat = "Mon, 02 Jan 2006 15:04:05 GMT"
)

// nowFunc is the clock used for the auto-injected Date header. Tests override
// it to get deterministic output; production leaves it at time.Now.
var nowFunc = time.Now

// WriteResponse serializes resp to w as a single buffered write, producing a
// well-formed HTTP/1.1 response. Headers Content-Length and Connection are
// always set by the serializer (overwriting any handler value). Date, Server,
// and Content-Type are filled in only when the handler did not provide them.
//
// On the wire, header names are canonicalized (Title-Cased on hyphen
// boundaries) and emitted in alphabetical order so output is deterministic.
func WriteResponse(w io.Writer, resp *ResponseWriter) error {
	if resp.Headers == nil {
		resp.Headers = make(map[string]string)
	}

	code := resp.StatusCode
	if code == 0 {
		code = 200
	}
	text, ok := statusTexts[code]
	if !ok {
		text = "Status"
	}

	// Always-overwrite headers.
	resp.Headers["content-length"] = strconv.Itoa(len(resp.Body))
	resp.Headers["connection"] = "close"

	// Default-only headers — preserve handler-supplied values.
	if _, ok := resp.Headers["date"]; !ok {
		resp.Headers["date"] = nowFunc().UTC().Format(httpDateFormat)
	}
	if _, ok := resp.Headers["server"]; !ok {
		resp.Headers["server"] = serverName
	}
	if _, ok := resp.Headers["content-type"]; !ok && len(resp.Body) > 0 {
		resp.Headers["content-type"] = "text/plain; charset=utf-8"
	}

	names := make([]string, 0, len(resp.Headers))
	for k := range resp.Headers {
		names = append(names, k)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", code, text)
	for _, name := range names {
		fmt.Fprintf(&buf, "%s: %s\r\n", canonicalHeaderName(name), resp.Headers[name])
	}
	buf.WriteString("\r\n")
	buf.Write(resp.Body)

	_, err := w.Write(buf.Bytes())
	return err
}

// WriteError writes a minimal plain-text response corresponding to err. Maps
// our parser sentinels to the matching 4xx/5xx code; falls back to 500 for
// anything we don't recognize. Useful for the server top-level handler that
// catches a ReadRequest failure.
func WriteError(w io.Writer, err error) error {
	code := 500
	switch {
	case errors.Is(err, ErrMalformed):
		code = 400
	case errors.Is(err, ErrLengthRequired):
		code = 411
	case errors.Is(err, ErrPayloadTooLarge):
		code = 413
	case errors.Is(err, ErrTooManyHeaders):
		code = 431
	case errors.Is(err, ErrVersionNotSupported):
		code = 505
	}
	text := statusTexts[code]
	body := fmt.Sprintf("%d %s\n", code, text)
	resp := &ResponseWriter{
		StatusCode: code,
		Headers:    map[string]string{},
		Body:       []byte(body),
	}
	return WriteResponse(w, resp)
}

// canonicalHeaderName returns name with the first character of each
// hyphen-separated segment uppercased and the rest lowercased
// ("content-type" → "Content-Type"). Idempotent on already-canonical input.
func canonicalHeaderName(name string) string {
	b := []byte(name)
	upper := true
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case upper && c >= 'a' && c <= 'z':
			b[i] = c - 32
		case !upper && c >= 'A' && c <= 'Z':
			b[i] = c + 32
		}
		upper = c == '-'
	}
	return string(b)
}
