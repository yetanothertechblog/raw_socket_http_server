package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// trustOurCertConfig builds a stdlib *crypto/tls.Config for a client that
// trusts only the cert embedded in identity. It also locks the negotiation
// to TLS 1.3 + x25519 + AES-128-GCM-SHA256, which is the only thing our
// server is willing to do.
func trustOurCertConfig(t *testing.T, identity *ServerIdentity) *stdtls.Config {
	t.Helper()
	cert, err := x509.ParseCertificate(identity.certDER)
	if err != nil {
		t.Fatalf("parse our cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &stdtls.Config{
		RootCAs:          pool,
		ServerName:       "localhost",
		MinVersion:       stdtls.VersionTLS13,
		MaxVersion:       stdtls.VersionTLS13,
		CurvePreferences: []stdtls.CurveID{stdtls.X25519},
		// We only support AES-128-GCM-SHA256, but Go's tls.Config only
		// honors CipherSuites for TLS 1.2; for 1.3 the suite is forced
		// by the client offering whatever it wants and the server picking.
		// Our server picks AES-128-GCM-SHA256 either way.
	}
}

// runHandshakeAgainstStdlib spins up our server-side handshake and a stdlib
// client over an in-memory net.Pipe and returns the connected pair after a
// successful handshake. It's the workhorse of the integration tests below.
//
// On any error in the goroutine, the channel surfaces the error so the test
// can fail without deadlocking on the second leg of the pipe.
func runHandshakeAgainstStdlib(t *testing.T, identity *ServerIdentity) (*Conn, *stdtls.Conn) {
	t.Helper()
	serverPipe, clientPipe := net.Pipe()
	t.Cleanup(func() {
		serverPipe.Close()
		clientPipe.Close()
	})

	serverConn := Server(serverPipe, identity)
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- serverConn.Handshake()
	}()

	clientConn := stdtls.Client(clientPipe, trustOurCertConfig(t, identity))
	if err := clientConn.HandshakeContext(timeoutCtx(t, 5*time.Second)); err != nil {
		// Drain the server side so the goroutine doesn't leak before we
		// fail. We can't use t.Cleanup to do this because we need to
		// surface the server-side reason here in the failure message.
		select {
		case sErr := <-serverErrCh:
			t.Fatalf("client Handshake: %v\nserver Handshake: %v", err, sErr)
		case <-time.After(time.Second):
			t.Fatalf("client Handshake: %v\nserver did not finish", err)
		}
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server Handshake: %v", err)
	}
	return serverConn, clientConn
}

// timeoutCtx is a tiny helper since net.Pipe() reads block forever on a
// stalled handshake — we want tests to fail fast rather than time out the
// whole test runner.
func timeoutCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// ----- the gold test ---------------------------------------------------------

// TestHandshake_AgainstStdlib_Echo is the highest-leverage test in the
// package: a stdlib TLS 1.3 client driving our server through the full
// handshake and exchanging plaintext over the encrypted tunnel. If anything
// is wrong with the wire format, key schedule, or signatures, this fails.
func TestHandshake_AgainstStdlib_Echo(t *testing.T) {
	identity, err := NewServerIdentity()
	if err != nil {
		t.Fatalf("NewServerIdentity: %v", err)
	}

	serverConn, clientConn := runHandshakeAgainstStdlib(t, identity)

	// Echo: client → server → client.
	go func() {
		buf := make([]byte, 32)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Errorf("server Read: %v", err)
			return
		}
		if _, err := serverConn.Write(buf[:n]); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}()

	const payload = "ping over our own TLS!"
	if _, err := clientConn.Write([]byte(payload)); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echo: got %q, want %q", got, payload)
	}
}

// TestHandshake_AgainstStdlib_LargeWrite forces our Write path to chunk
// across multiple records (>16 KiB). The stdlib client transparently
// reassembles them.
func TestHandshake_AgainstStdlib_LargeWrite(t *testing.T) {
	identity, err := NewServerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := runHandshakeAgainstStdlib(t, identity)

	// 40 KiB — straddles two record boundaries (16 KiB each).
	payload := bytes.Repeat([]byte("ABCDEFGH"), 5120)

	go func() {
		if _, err := serverConn.Write(payload); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch")
	}
}

// TestHandshake_AgainstStdlib_CertVerifies confirms that the stdlib client
// successfully validated our self-signed cert (against its root pool) AND
// our CertificateVerify signature — both implicit in HandshakeContext
// returning nil, but we also peek at ConnectionState to make it explicit.
func TestHandshake_AgainstStdlib_CertVerifies(t *testing.T) {
	identity, err := NewServerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, clientConn := runHandshakeAgainstStdlib(t, identity)

	state := clientConn.ConnectionState()
	if state.Version != stdtls.VersionTLS13 {
		t.Errorf("negotiated version = %#x, want TLS 1.3", state.Version)
	}
	if state.CipherSuite != stdtls.TLS_AES_128_GCM_SHA256 {
		t.Errorf("cipher suite = %#x, want TLS_AES_128_GCM_SHA256", state.CipherSuite)
	}
	if !state.HandshakeComplete {
		t.Errorf("HandshakeComplete = false")
	}
	if len(state.PeerCertificates) != 1 {
		t.Fatalf("PeerCertificates len = %d, want 1", len(state.PeerCertificates))
	}
	if !bytes.Equal(state.PeerCertificates[0].Raw, identity.certDER) {
		t.Errorf("peer cert raw bytes don't match server identity")
	}
}

// ----- failure-path tests ----------------------------------------------------

// TestHandshake_RejectsClientWithoutTLS13 simulates a client that doesn't
// offer TLS 1.3 (we hand-craft the ClientHello). validateClientHello must
// reject it; the connection error must surface through Handshake().
func TestHandshake_RejectsClientWithoutTLS13(t *testing.T) {
	hello := &clientHello{
		cipherSuites:        []uint16{cipherTLSAES128GCMSHA256},
		supportedVersions:   []uint16{0x0303}, // only TLS 1.2
		supportedGroups:     []uint16{namedGroupX25519},
		signatureAlgorithms: []uint16{sigSchemeECDSAP256SHA256},
		keyShares:           []keyShareEntry{{group: namedGroupX25519, keyExchange: bytes.Repeat([]byte{0x01}, 32)}},
	}
	if err := validateClientHello(hello); err == nil {
		t.Errorf("expected error when supported_versions lacks TLS 1.3")
	}
}

func TestHandshake_RejectsClientWithoutX25519(t *testing.T) {
	hello := &clientHello{
		cipherSuites:        []uint16{cipherTLSAES128GCMSHA256},
		supportedVersions:   []uint16{tls13Version},
		supportedGroups:     []uint16{0x0017}, // secp256r1 only
		signatureAlgorithms: []uint16{sigSchemeECDSAP256SHA256},
	}
	if err := validateClientHello(hello); err == nil {
		t.Errorf("expected error when x25519 not offered")
	}
}

func TestHandshake_RejectsX25519GroupWithoutKeyShare(t *testing.T) {
	hello := &clientHello{
		cipherSuites:        []uint16{cipherTLSAES128GCMSHA256},
		supportedVersions:   []uint16{tls13Version},
		supportedGroups:     []uint16{namedGroupX25519},
		signatureAlgorithms: []uint16{sigSchemeECDSAP256SHA256},
		// No keyShares — the only way the client can offer x25519 in
		// supported_groups but send no key_share is to expect HRR. We
		// don't implement HRR.
	}
	if err := validateClientHello(hello); err == nil {
		t.Errorf("expected error when x25519 group offered without key_share")
	}
}

func TestHandshake_RejectsBadKeyShareLength(t *testing.T) {
	hello := &clientHello{
		cipherSuites:        []uint16{cipherTLSAES128GCMSHA256},
		supportedVersions:   []uint16{tls13Version},
		supportedGroups:     []uint16{namedGroupX25519},
		signatureAlgorithms: []uint16{sigSchemeECDSAP256SHA256},
		keyShares:           []keyShareEntry{{group: namedGroupX25519, keyExchange: []byte{0x01}}}, // 1 byte
	}
	if err := validateClientHello(hello); err == nil {
		t.Errorf("expected error on short x25519 key_share")
	}
}

// TestHandshake_HandshakeIsIdempotent: a second Handshake() call after a
// successful one must be a cheap no-op, not redo the handshake.
func TestHandshake_HandshakeIsIdempotent(t *testing.T) {
	identity, _ := NewServerIdentity()
	serverConn, _ := runHandshakeAgainstStdlib(t, identity)

	// Disable the underlying transport — if a second Handshake actually
	// did I/O, it would fail.
	serverConn.raw = errReadWriter{}
	if err := serverConn.Handshake(); err != nil {
		t.Errorf("second Handshake returned error: %v", err)
	}
}

// TestHandshake_HandshakeErrorIsSticky: after a Handshake failure, the
// recorded error is returned by every subsequent call rather than re-running
// the handshake.
func TestHandshake_HandshakeErrorIsSticky(t *testing.T) {
	c := &Conn{
		raw:          alwaysEOF{},
		identity:     nil, // forces validation error before any I/O
		handshakeErr: errors.New("baked-in failure"),
	}
	if err := c.Handshake(); err == nil || err.Error() != "baked-in failure" {
		t.Errorf("Handshake() = %v, want sticky baked-in failure", err)
	}
}

// ----- transcript helpers ----------------------------------------------------

// TestTranscript_RunningHashEqualsOneShot pins down that update+sum equals
// a single Hash(concat). This is what RFC 8446 §4.4.1 mandates and what
// every other end of the handshake relies on.
func TestTranscript_RunningHashEqualsOneShot(t *testing.T) {
	tx := newTranscript()
	parts := [][]byte{
		[]byte("first message"),
		[]byte("second message"),
		bytes.Repeat([]byte{0x42}, 200),
	}
	for _, p := range parts {
		tx.update(p)
	}
	got := tx.sum()

	want := sha256.Sum256(bytes.Join(parts, nil))
	if !bytes.Equal(got, want[:]) {
		t.Errorf("running sum = %x, want %x", got, want)
	}
}

// TestTranscript_SumDoesNotResetState: pulling sum() midway must not
// disturb the rolling hash, so subsequent updates extend the same digest.
func TestTranscript_SumDoesNotResetState(t *testing.T) {
	tx := newTranscript()
	tx.update([]byte("hello "))
	mid := tx.sum()
	tx.update([]byte("world"))
	end := tx.sum()

	if bytes.Equal(mid, end) {
		t.Errorf("mid and end sums identical — sum() reset state?")
	}
	want := sha256.Sum256([]byte("hello world"))
	if !bytes.Equal(end, want[:]) {
		t.Errorf("end sum = %x, want %x", end, want)
	}
}

// ----- verifyData ------------------------------------------------------------

// TestVerifyData_HMACShape sanity-checks that verifyData produces a 32-byte
// HMAC and that distinct transcripts produce distinct outputs.
func TestVerifyData_HMACShape(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAA}, 32)
	a := verifyData(secret, bytes.Repeat([]byte{0x01}, 32))
	b := verifyData(secret, bytes.Repeat([]byte{0x02}, 32))
	if len(a) != 32 || len(b) != 32 {
		t.Errorf("len = %d / %d, want 32", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Errorf("verifyData identical for different transcripts")
	}
}

// ----- small test utilities --------------------------------------------------

// errReadWriter fails any I/O — used to detect accidental I/O from idempotent
// Handshake calls.
type errReadWriter struct{}

func (errReadWriter) Read([]byte) (int, error)  { return 0, errors.New("Read called") }
func (errReadWriter) Write([]byte) (int, error) { return 0, errors.New("Write called") }

// alwaysEOF returns io.EOF on read, which would normally fail the handshake.
type alwaysEOF struct{}

func (alwaysEOF) Read([]byte) (int, error)  { return 0, io.EOF }
func (alwaysEOF) Write([]byte) (int, error) { return 0, fmt.Errorf("unexpected write") }
