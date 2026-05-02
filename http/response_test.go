package http

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedTime gives deterministic Date headers in tests that compare bytes.
func fixedTime() time.Time {
	return time.Date(2026, 5, 2, 14, 23, 1, 0, time.UTC)
}

func withFixedClock(t *testing.T) {
	t.Helper()
	prev := nowFunc
	nowFunc = fixedTime
	t.Cleanup(func() { nowFunc = prev })
}

func TestWriteResponse_Basic200(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{},
		Body:       []byte("Hello"),
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	want := "HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 5\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Date: Sat, 02 May 2026 14:23:01 GMT\r\n" +
		"Server: rawhttp\r\n" +
		"\r\n" +
		"Hello"
	if got := buf.String(); got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestWriteResponse_404(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 404,
		Headers:    map[string]string{},
		Body:       []byte("nope"),
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "HTTP/1.1 404 Not Found\r\n") {
		t.Errorf("status line wrong: %q", buf.String())
	}
}

func TestWriteResponse_UnknownStatusCodeFallback(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 799,
		Headers:    map[string]string{},
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "HTTP/1.1 799 Status\r\n") {
		t.Errorf("status line wrong: %q", buf.String())
	}
}

func TestWriteResponse_ZeroStatusDefaultsTo200(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		Headers: map[string]string{},
		Body:    []byte("ok"),
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "HTTP/1.1 200 OK\r\n") {
		t.Errorf("status line wrong: %q", buf.String())
	}
}

func TestWriteResponse_ContentLengthAlwaysOverwritten(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{"content-length": "999"}, // wrong on purpose
		Body:       []byte("Hello"),
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Content-Length: 5\r\n") {
		t.Errorf("expected Content-Length to be overwritten to 5, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "Content-Length: 999") {
		t.Errorf("handler-supplied wrong Content-Length leaked through")
	}
}

func TestWriteResponse_DateAutoAdded(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{},
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Date: Sat, 02 May 2026 14:23:01 GMT\r\n") {
		t.Errorf("expected Date header, got:\n%s", buf.String())
	}
}

func TestWriteResponse_DatePreservedIfSet(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{"date": "Mon, 01 Jan 1990 00:00:00 GMT"},
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Date: Mon, 01 Jan 1990 00:00:00 GMT\r\n") {
		t.Errorf("handler Date was overwritten:\n%s", buf.String())
	}
}

func TestWriteResponse_ServerAutoAdded(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{StatusCode: 200, Headers: map[string]string{}}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Server: rawhttp\r\n") {
		t.Errorf("expected Server header, got:\n%s", buf.String())
	}
}

func TestWriteResponse_ContentTypeOnlyWhenBody(t *testing.T) {
	withFixedClock(t)

	// No body → no Content-Type auto-add.
	resp := &ResponseWriter{StatusCode: 204, Headers: map[string]string{}}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Content-Type") {
		t.Errorf("204 with empty body should not auto-add Content-Type:\n%s", buf.String())
	}

	// Body present → Content-Type auto-added.
	resp = &ResponseWriter{StatusCode: 200, Headers: map[string]string{}, Body: []byte("x")}
	buf.Reset()
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Content-Type: text/plain; charset=utf-8\r\n") {
		t.Errorf("expected default Content-Type, got:\n%s", buf.String())
	}
}

func TestWriteResponse_ContentTypePreserved(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"a":1}`),
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Content-Type: application/json\r\n") {
		t.Errorf("handler Content-Type was overwritten:\n%s", buf.String())
	}
}

func TestWriteResponse_ConnectionCloseAlways(t *testing.T) {
	withFixedClock(t)
	// Even if handler tries to ask for keep-alive, we force close.
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{"connection": "keep-alive"},
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Connection: close\r\n") {
		t.Errorf("Connection should be forced to close:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "Connection: keep-alive") {
		t.Errorf("keep-alive leaked through")
	}
}

func TestWriteResponse_HeaderNamesCanonicalized(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers: map[string]string{
			"x-forwarded-for": "1.1.1.1",
			"x-custom":        "v",
		},
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "X-Forwarded-For: 1.1.1.1\r\n") {
		t.Errorf("X-Forwarded-For not canonicalized:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "X-Custom: v\r\n") {
		t.Errorf("X-Custom not canonicalized:\n%s", buf.String())
	}
}

func TestWriteResponse_NilHeadersMap(t *testing.T) {
	withFixedClock(t)
	// Defensive: a handler that constructed the writer manually with nil Headers.
	resp := &ResponseWriter{StatusCode: 200, Body: []byte("x")}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Content-Length: 1\r\n") {
		t.Errorf("expected Content-Length: 1 with nil headers, got:\n%s", buf.String())
	}
}

func TestCanonicalHeaderName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"content-type", "Content-Type"},
		{"x-forwarded-for", "X-Forwarded-For"},
		{"host", "Host"},
		{"Content-Type", "Content-Type"},          // idempotent
		{"CONTENT-TYPE", "Content-Type"},          // re-cases
		{"x-CUSTOM-thing", "X-Custom-Thing"},      // mixed
		{"", ""},
		{"-", "-"},
		{"a", "A"},
	}
	for _, tc := range cases {
		if got := canonicalHeaderName(tc.in); got != tc.want {
			t.Errorf("canonicalHeaderName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWriteError_MapsErrors(t *testing.T) {
	withFixedClock(t)
	cases := []struct {
		err  error
		code string
	}{
		{ErrMalformed, "400"},
		{ErrLengthRequired, "411"},
		{ErrPayloadTooLarge, "413"},
		{ErrTooManyHeaders, "431"},
		{ErrVersionNotSupported, "505"},
		{errors.New("something else"), "500"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteError(&buf, tc.err); err != nil {
			t.Fatal(err)
		}
		want := "HTTP/1.1 " + tc.code + " "
		if !strings.HasPrefix(buf.String(), want) {
			t.Errorf("WriteError(%v) start = %q, want prefix %q",
				tc.err, firstLine(buf.String()), want)
		}
	}
}

// Round-trip: serialize a response, then make sure all the structural pieces
// look right (status line first, blank line between headers and body, body
// bytes verbatim).
func TestWriteResponse_Structure(t *testing.T) {
	withFixedClock(t)
	resp := &ResponseWriter{
		StatusCode: 200,
		Headers:    map[string]string{},
		Body:       []byte("body bytes"),
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, resp); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Status line first.
	if !strings.HasPrefix(out, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("status line wrong: %q", firstLine(out))
	}

	// Header/body separator.
	sep := strings.Index(out, "\r\n\r\n")
	if sep == -1 {
		t.Fatalf("missing header/body separator")
	}

	body := out[sep+4:]
	if body != "body bytes" {
		t.Errorf("body = %q, want %q", body, "body bytes")
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i != -1 {
		return s[:i]
	}
	return s
}
