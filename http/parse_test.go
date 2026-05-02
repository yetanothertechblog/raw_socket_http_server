package http

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadRequest_GET(t *testing.T) {
	raw := "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.Path != "/foo" {
		t.Errorf("Path = %q, want /foo", req.Path)
	}
	if req.Version != "HTTP/1.1" {
		t.Errorf("Version = %q, want HTTP/1.1", req.Version)
	}
	if got := req.Headers["host"]; got != "example.com" {
		t.Errorf("Headers[host] = %q, want example.com", got)
	}
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
}

func TestReadRequest_POSTWithBody(t *testing.T) {
	body := "name=ada&role=admin"
	raw := "POST /submit HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"\r\n" + body
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if string(req.Body) != body {
		t.Errorf("Body = %q, want %q", req.Body, body)
	}
}

func TestReadRequest_HeaderNamesLowercased(t *testing.T) {
	raw := "GET / HTTP/1.1\r\n" +
		"HOST: example.com\r\n" +
		"User-Agent: curl/8\r\n" +
		"\r\n"
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Headers["host"] != "example.com" {
		t.Errorf("Headers[host] = %q", req.Headers["host"])
	}
	if req.Headers["user-agent"] != "curl/8" {
		t.Errorf("Headers[user-agent] = %q", req.Headers["user-agent"])
	}
	if _, ok := req.Headers["HOST"]; ok {
		t.Errorf("found HOST in lowercased map")
	}
}

func TestReadRequest_DuplicateHeadersJoined(t *testing.T) {
	raw := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Forwarded-For: 1.1.1.1\r\n" +
		"X-Forwarded-For: 2.2.2.2\r\n" +
		"\r\n"
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := req.Headers["x-forwarded-for"], "1.1.1.1, 2.2.2.2"; got != want {
		t.Errorf("Headers[x-forwarded-for] = %q, want %q", got, want)
	}
}

func TestReadRequest_HeaderValueTrimmed(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost:  \texample.com\t  \r\n\r\n"
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Headers["host"] != "example.com" {
		t.Errorf("Headers[host] = %q, want example.com (trimmed)", req.Headers["host"])
	}
}

func TestReadRequest_Errors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{
			name: "missing Host header",
			raw:  "GET / HTTP/1.1\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "HTTP/1.0 not supported",
			raw:  "GET / HTTP/1.0\r\nHost: x\r\n\r\n",
			want: ErrVersionNotSupported,
		},
		{
			name: "garbage version token",
			raw:  "GET / FTP/9.9\r\nHost: x\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "missing path",
			raw:  "GET HTTP/1.1\r\nHost: x\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "non-origin-form path",
			raw:  "GET foo HTTP/1.1\r\nHost: x\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "lowercase method allowed only as token; bad method char",
			raw:  "GE T / HTTP/1.1\r\nHost: x\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "header with space before colon",
			raw:  "GET / HTTP/1.1\r\nHost : x\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "obs-fold header (continuation)",
			raw:  "GET / HTTP/1.1\r\nHost: x\r\nX-Long: a,\r\n b\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "POST without Content-Length",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\n\r\n",
			want: ErrLengthRequired,
		},
		{
			name: "negative Content-Length",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "non-numeric Content-Length",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",
			want: ErrMalformed,
		},
		{
			name: "Content-Length exceeds max body",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n",
			want: ErrPayloadTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadRequest(strings.NewReader(tc.raw))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadRequest_BodyTruncated(t *testing.T) {
	// Content-Length claims 10, only 4 bytes provided.
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabcd"
	_, err := ReadRequest(strings.NewReader(raw))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadRequest_EmptyInput(t *testing.T) {
	// Clean EOF before any bytes — connection closed without sending a request.
	// Should propagate as io.EOF so the caller can close quietly.
	_, err := ReadRequest(strings.NewReader(""))
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

func TestReadRequest_RequestLineTooLong(t *testing.T) {
	// Build a path larger than maxRequestLine.
	long := strings.Repeat("a", maxRequestLine+1)
	raw := "GET /" + long + " HTTP/1.1\r\nHost: x\r\n\r\n"
	_, err := ReadRequest(strings.NewReader(raw))
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestReadRequest_TooManyHeaders(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: x\r\n")
	for i := 0; i < maxHeaders+5; i++ {
		b.WriteString("X-Pad-")
		b.WriteString(itoa(i))
		b.WriteString(": v\r\n")
	}
	b.WriteString("\r\n")
	_, err := ReadRequest(strings.NewReader(b.String()))
	if !errors.Is(err, ErrTooManyHeaders) {
		t.Errorf("err = %v, want ErrTooManyHeaders", err)
	}
}

func TestReadRequest_LFOnly(t *testing.T) {
	// RFC 7230 says servers SHOULD accept bare LF as line terminator. We do.
	raw := "GET / HTTP/1.1\nHost: example.com\n\n"
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Headers["host"] != "example.com" {
		t.Errorf("Headers[host] = %q", req.Headers["host"])
	}
}

func TestReadRequest_ZeroContentLength(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
	req, err := ReadRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.Body) != 0 {
		t.Errorf("Body = %q, want empty", req.Body)
	}
}

// itoa avoids importing strconv into the test file (it's in the package proper)
// and keeps test-build dependencies minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
