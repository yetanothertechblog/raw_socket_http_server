package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	parsedPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if parsedPub.Curve != elliptic.P256() {
		t.Errorf("cert pub curve = %v, want P-256", parsedPub.Curve.Params().Name)
	}
	if parsedPub.X.Cmp(s.priv.PublicKey.X) != 0 || parsedPub.Y.Cmp(s.priv.PublicKey.Y) != 0 {
		t.Errorf("cert pub != identity priv.PublicKey")
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
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA256", cert.SignatureAlgorithm)
	}
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
}

func TestGenerateServerIdentity_FreshKeysEachCall(t *testing.T) {
	a := freshIdentity(t)
	b := freshIdentity(t)
	if a.priv.D.Cmp(b.priv.D) == 0 {
		t.Errorf("two generations produced the same private scalar — RNG bug?")
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

	sig, err := s.signCertificateVerify(transcript)
	if err != nil {
		t.Fatalf("signCertificateVerify: %v", err)
	}
	digest := sha256.Sum256(certificateVerifySignInput(transcript))

	if !ecdsa.VerifyASN1(&s.priv.PublicKey, digest[:], sig) {
		t.Errorf("ecdsa.VerifyASN1 failed under our own public key")
	}
}

// TestSignCertificateVerify_OutputIsDERSequence: the wire format for ECDSA
// in TLS 1.3 is the DER encoding of ECDSA-Sig-Value (RFC 5480) — a SEQUENCE
// of two INTEGERs. The first byte is the SEQUENCE tag (0x30).
func TestSignCertificateVerify_OutputIsDERSequence(t *testing.T) {
	s := freshIdentity(t)
	sig, err := s.signCertificateVerify(make([]byte, sha256.Size))
	if err != nil {
		t.Fatalf("signCertificateVerify: %v", err)
	}
	if len(sig) < 8 || sig[0] != 0x30 {
		t.Errorf("sig is not a DER SEQUENCE (first byte %#x, len %d)", sig[0], len(sig))
	}
	// Sanity bound: P-256 r,s are each ≤ 32 bytes; with DER overhead the
	// total fits comfortably under 80 bytes.
	if len(sig) > 80 {
		t.Errorf("sig length %d unexpectedly large for P-256", len(sig))
	}
}

// TestSignCertificateVerify_DependsOnTranscript: a different transcript must
// produce a verifiable signature whose payload commits to the new transcript.
// ECDSA is randomized so we can't compare bytes — instead we verify each
// signature against its own digest and confirm cross-verification fails.
func TestSignCertificateVerify_DependsOnTranscript(t *testing.T) {
	s := freshIdentity(t)
	tA := bytes.Repeat([]byte{0x01}, sha256.Size)
	tB := bytes.Repeat([]byte{0x02}, sha256.Size)

	sigA, err := s.signCertificateVerify(tA)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := s.signCertificateVerify(tB)
	if err != nil {
		t.Fatal(err)
	}

	digestA := sha256.Sum256(certificateVerifySignInput(tA))
	digestB := sha256.Sum256(certificateVerifySignInput(tB))

	if !ecdsa.VerifyASN1(&s.priv.PublicKey, digestA[:], sigA) {
		t.Errorf("sigA does not verify against digestA")
	}
	if !ecdsa.VerifyASN1(&s.priv.PublicKey, digestB[:], sigB) {
		t.Errorf("sigB does not verify against digestB")
	}
	// Cross-verify: a signature for transcript A must NOT validate against
	// transcript B's digest. This is what catches "transcript ignored" bugs.
	if ecdsa.VerifyASN1(&s.priv.PublicKey, digestB[:], sigA) {
		t.Errorf("sigA verified under digestB — transcript not bound into signature")
	}
}

// TestSignCertificateVerify_RejectsForgery: a signature from one identity
// must not verify under another's public key. Catches accidental swap of
// pub/priv keys in NewServerIdentity.
func TestSignCertificateVerify_RejectsForgery(t *testing.T) {
	a := freshIdentity(t)
	b := freshIdentity(t)
	transcript := bytes.Repeat([]byte{0x77}, sha256.Size)

	sig, err := a.signCertificateVerify(transcript)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(certificateVerifySignInput(transcript))

	if ecdsa.VerifyASN1(&b.priv.PublicKey, digest[:], sig) {
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
