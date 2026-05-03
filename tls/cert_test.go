package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// freshIdentity returns a server identity for tests, failing the test on any
// generation error so test bodies don't have to keep re-asserting err == nil.
func freshIdentity(t *testing.T) *ServerIdentity {
	t.Helper()
	s, err := NewServerIdentity()
	if err != nil {
		t.Fatalf("NewServerIdentity: %v", err)
	}
	return s
}

// parseCert parses the DER bytes our identity produced and returns the
// x509.Certificate so tests can inspect specific fields.
func parseCert(t *testing.T, s *ServerIdentity) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(s.certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestGenerateServerIdentity_DERIsParseable(t *testing.T) {
	s := freshIdentity(t)
	if len(s.certDER) == 0 {
		t.Fatalf("certDER is empty")
	}
	parseCert(t, s) // parse-or-fail is the assertion
}

func TestGenerateServerIdentity_PublicKeyMatches(t *testing.T) {
	s := freshIdentity(t)
	cert := parseCert(t, s)

	parsedPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("cert public key type = %T, want ed25519.PublicKey", cert.PublicKey)
	}
	if !bytes.Equal(parsedPub, s.pub) {
		t.Errorf("cert pub != identity pub\n cert:     %x\n identity: %x", parsedPub, s.pub)
	}

	// Sanity: the private key's public half should match too.
	derivedPub, ok := s.priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() type = %T", s.priv.Public())
	}
	if !bytes.Equal(derivedPub, s.pub) {
		t.Errorf("priv.Public() != identity pub")
	}
}

func TestGenerateServerIdentity_Validity(t *testing.T) {
	s := freshIdentity(t)
	cert := parseCert(t, s)

	now := time.Now()
	if !cert.NotBefore.Before(now) {
		t.Errorf("NotBefore (%v) should be before now (%v)", cert.NotBefore, now)
	}
	if !cert.NotAfter.After(now) {
		t.Errorf("NotAfter (%v) should be after now (%v)", cert.NotAfter, now)
	}

	// NotAfter ≈ now + certValidity, within a small slop for execution time.
	expected := now.Add(certValidity)
	delta := cert.NotAfter.Sub(expected)
	if delta < -2*time.Minute || delta > 2*time.Minute {
		t.Errorf("NotAfter = %v, expected ≈ %v (delta %v)", cert.NotAfter, expected, delta)
	}
}

func TestGenerateServerIdentity_SAN(t *testing.T) {
	cert := parseCert(t, freshIdentity(t))

	if !contains(cert.DNSNames, "localhost") {
		t.Errorf("DNSNames missing localhost: %v", cert.DNSNames)
	}

	wantIPs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	for _, want := range wantIPs {
		found := false
		for _, got := range cert.IPAddresses {
			if got.Equal(want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IPAddresses missing %v: %v", want, cert.IPAddresses)
		}
	}
}

func TestGenerateServerIdentity_KeyUsages(t *testing.T) {
	cert := parseCert(t, freshIdentity(t))

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("KeyUsage missing DigitalSignature: %v", cert.KeyUsage)
	}
	// In TLS 1.3 we don't use any other KeyUsage; assert it's the *only*
	// bit set so we notice if anyone widens it accidentally.
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want exactly DigitalSignature", cert.KeyUsage)
	}

	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Errorf("ExtKeyUsage missing ServerAuth: %v", cert.ExtKeyUsage)
	}
}

func TestGenerateServerIdentity_NotCA(t *testing.T) {
	cert := parseCert(t, freshIdentity(t))
	if !cert.BasicConstraintsValid {
		t.Errorf("BasicConstraintsValid = false")
	}
	if cert.IsCA {
		t.Errorf("IsCA = true, want false (this is a leaf cert)")
	}
}

// TestGenerateServerIdentity_SelfSignatureVerifies confirms that the cert is
// genuinely self-signed: its embedded signature verifies under its own
// public key. We bypass CheckSignatureFrom because that helper insists the
// parent be marked as a CA (with KeyUsage.keyCertSign), which our leaf cert
// deliberately is not. CheckSignature does the cryptographic check directly.
func TestGenerateServerIdentity_SelfSignatureVerifies(t *testing.T) {
	cert := parseCert(t, freshIdentity(t))
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
}

func TestGenerateServerIdentity_FreshKeysEachCall(t *testing.T) {
	a := freshIdentity(t)
	b := freshIdentity(t)
	if bytes.Equal(a.pub, b.pub) {
		t.Errorf("two generations produced the same public key — RNG bug?")
	}
	if bytes.Equal(a.certDER, b.certDER) {
		t.Errorf("two generations produced the same cert DER")
	}
}

// TestGenerateServerIdentity_UniqueSerials guards against accidentally
// hardcoding the serial number.
func TestGenerateServerIdentity_UniqueSerials(t *testing.T) {
	a := parseCert(t, freshIdentity(t))
	b := parseCert(t, freshIdentity(t))
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Errorf("two generations used the same serial: %s", a.SerialNumber)
	}
}

// --- CertificateVerify --------------------------------------------------------

// TestCertificateVerifySignInput_Layout pins down the exact 130-byte sign
// input layout from RFC 8446 §4.4.3. If we ever drift here, no client will
// accept our CertificateVerify, and that failure is much easier to debug
// from a unit test than from a TLS alert.
func TestCertificateVerifySignInput_Layout(t *testing.T) {
	transcript := bytes.Repeat([]byte{0xAB}, sha256.Size)
	got := certificateVerifySignInput(transcript)

	if len(got) != 130 {
		t.Errorf("len = %d, want 130", len(got))
	}
	// First 64 bytes: 0x20 spaces.
	for i := 0; i < 64; i++ {
		if got[i] != 0x20 {
			t.Errorf("byte %d = %02x, want 20", i, got[i])
		}
	}
	// Then the 33-byte ASCII context string.
	const ctx = "TLS 1.3, server CertificateVerify"
	if string(got[64:64+len(ctx)]) != ctx {
		t.Errorf("context string = %q, want %q", got[64:64+len(ctx)], ctx)
	}
	// Then the 0x00 separator.
	sepIdx := 64 + len(ctx)
	if got[sepIdx] != 0x00 {
		t.Errorf("separator byte = %02x, want 00", got[sepIdx])
	}
	// Then the transcript hash, byte-for-byte.
	if !bytes.Equal(got[sepIdx+1:], transcript) {
		t.Errorf("trailing hash = %x, want %x", got[sepIdx+1:], transcript)
	}
}

func TestCertificateVerifySignInput_NoLeakBetweenCalls(t *testing.T) {
	// If the build accidentally shared a buffer, calling twice with
	// different transcripts would corrupt the first result.
	a := certificateVerifySignInput(bytes.Repeat([]byte{0x01}, sha256.Size))
	b := certificateVerifySignInput(bytes.Repeat([]byte{0x02}, sha256.Size))

	// The trailing 32 bytes must differ.
	if bytes.Equal(a[len(a)-sha256.Size:], b[len(b)-sha256.Size:]) {
		t.Errorf("two distinct transcripts produced the same trailing hash")
	}
	// The leading 98 prefix bytes must be identical.
	const prefixLen = 64 + len("TLS 1.3, server CertificateVerify") + 1
	if !bytes.Equal(a[:prefixLen], b[:prefixLen]) {
		t.Errorf("prefix bytes differ between calls")
	}
}

func TestSignCertificateVerify_VerifiesUnderOwnPubKey(t *testing.T) {
	s := freshIdentity(t)
	transcript := bytes.Repeat([]byte{0xCD}, sha256.Size)

	sig := s.signCertificateVerify(transcript)
	input := certificateVerifySignInput(transcript)

	if !ed25519.Verify(s.pub, input, sig) {
		t.Errorf("ed25519.Verify failed under our own public key")
	}
}

func TestSignCertificateVerify_OutputLength(t *testing.T) {
	s := freshIdentity(t)
	sig := s.signCertificateVerify(make([]byte, sha256.Size))
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("sig length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
}

// TestSignCertificateVerify_DependsOnTranscript: a different transcript must
// produce a different signature. ed25519 is deterministic, so this also
// catches the bug where the transcript argument is silently ignored.
func TestSignCertificateVerify_DependsOnTranscript(t *testing.T) {
	s := freshIdentity(t)
	a := s.signCertificateVerify(bytes.Repeat([]byte{0x01}, sha256.Size))
	b := s.signCertificateVerify(bytes.Repeat([]byte{0x02}, sha256.Size))
	if bytes.Equal(a, b) {
		t.Errorf("signatures identical for different transcripts")
	}
}

// TestSignCertificateVerify_DeterministicForSameInputs: ed25519 is RFC 8032-
// deterministic — same key + same message → same signature, every time. If
// this test ever flakes, something is mixing entropy into the signing path.
func TestSignCertificateVerify_DeterministicForSameInputs(t *testing.T) {
	s := freshIdentity(t)
	transcript := bytes.Repeat([]byte{0xEE}, sha256.Size)
	a := s.signCertificateVerify(transcript)
	b := s.signCertificateVerify(transcript)
	if !bytes.Equal(a, b) {
		t.Errorf("ed25519 produced non-deterministic signatures")
	}
}

// TestSignCertificateVerify_RejectsForgery: a signature from one identity
// must not verify under another's public key. Catches accidental swap of
// pub/priv keys in NewServerIdentity.
func TestSignCertificateVerify_RejectsForgery(t *testing.T) {
	a := freshIdentity(t)
	b := freshIdentity(t)
	transcript := bytes.Repeat([]byte{0x77}, sha256.Size)

	sig := a.signCertificateVerify(transcript)
	input := certificateVerifySignInput(transcript)

	if ed25519.Verify(b.pub, input, sig) {
		t.Errorf("signature from identity A verified under identity B's pubkey")
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
