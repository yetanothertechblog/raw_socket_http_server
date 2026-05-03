package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// Server identity: the self-signed cert we ship in the Certificate handshake
// message and the private key we use to sign CertificateVerify.
//
// Scope: ECDSA P-256 with SHA-256 (TLS 1.3 sig scheme 0x0403), single
// self-signed leaf cert (no chain), generated fresh in memory at server
// start. Curl will need -k anyway since the cert isn't trust-anchored, so
// there's nothing to gain from persisting it.
//
// Why ECDSA P-256 rather than ed25519: macOS curl (LibreSSL/SecureTransport
// backends) does not advertise ed25519 in TLS 1.3 signature_algorithms, so
// our server's policy check used to reject every macOS curl client. ECDSA
// P-256 is universally offered by every TLS 1.3 client we care about
// (curl across all backends, browsers, the Go stdlib).
//
// SANs cover localhost / 127.0.0.1 / ::1, which is everything our local
// test setup exercises. To run on a real hostname you'd add it to
// NewServerIdentity's DNSNames slice.

// certificateVerifyContextServer is the ASCII context string that goes into
// the CertificateVerify sign input (RFC 8446 §4.4.3). The matching client
// string would be "TLS 1.3, client CertificateVerify" — we don't generate
// that since we never speak as a TLS client.
const certificateVerifyContextServer = "TLS 1.3, server CertificateVerify"

// certValidity is how long the generated cert lives. We pick "essentially
// forever" because the cert is regenerated every server start, so its
// expiration date never matters in practice.
const certValidity = 10 * 365 * 24 * time.Hour

// certClockSkew is subtracted from NotBefore so a client whose clock is
// slightly ahead of ours doesn't reject the cert as not-yet-valid.
const certClockSkew = time.Minute

// ServerIdentity bundles everything the handshake needs about the server's
// own keypair.
type ServerIdentity struct {
	// certDER is the X.509 certificate in DER form. It ships verbatim as
	// the single entry of the Certificate handshake message's
	// certificate_list (RFC 8446 §4.4.2).
	certDER []byte

	priv *ecdsa.PrivateKey
}

// NewServerIdentity creates a fresh self-signed ECDSA P-256 cert covering
// localhost / 127.0.0.1 / ::1, valid for ~10 years. Called once at startup;
// the result is shared across every TLS connection the server accepts.
func NewServerIdentity() (*ServerIdentity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// 128-bit random serial. RFC 5280 §4.1.2.2 requires a positive integer
	// of up to 20 octets; modern best practice is ≥64 bits of randomness so
	// serials are effectively unique without a database.
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rawhttp"},
		NotBefore:    now.Add(-certClockSkew),
		NotAfter:     now.Add(certValidity),

		// KeyUsage = digitalSignature: this key is allowed to sign
		// CertificateVerify (and TLS 1.2's ServerKeyExchange, but we don't
		// speak that). No keyEncipherment because TLS 1.3 doesn't use RSA
		// key transport.
		KeyUsage: x509.KeyUsageDigitalSignature,

		// ExtKeyUsage = serverAuth: this cert may authenticate a server.
		// Required by most verifiers even when the user passes -k.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// SANs that match our local-test endpoints. Modern verifiers
		// ignore CommonName for hostname matching; SAN is what counts.
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},

		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Self-signed: parent == template, signed under our own private key.
	// x509.CreateCertificate picks ECDSAWithSHA256 automatically for a
	// P-256 key.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return &ServerIdentity{
		certDER: certDER,
		priv:    priv,
	}, nil
}

// certificateVerifySignInput builds the exact byte string the server signs
// for the CertificateVerify message (RFC 8446 §4.4.3):
//
//	64 × 0x20                              // 64 ASCII spaces
//	|| "TLS 1.3, server CertificateVerify" // 33 ASCII bytes
//	|| 0x00                                 // separator
//	|| transcriptHash                       // 32 bytes for SHA-256
//	= 130 bytes total
//
// The leading 64 spaces and context string are domain-separation guards: any
// stray protocol that signs raw transcript hashes would still fail to forge
// a valid CertificateVerify because of the prefix.
func certificateVerifySignInput(transcriptHash []byte) []byte {
	const spaceCount = 64
	out := make([]byte, 0, spaceCount+len(certificateVerifyContextServer)+1+len(transcriptHash))
	for i := 0; i < spaceCount; i++ {
		out = append(out, 0x20)
	}
	out = append(out, certificateVerifyContextServer...)
	out = append(out, 0x00)
	out = append(out, transcriptHash...)
	return out
}

// signCertificateVerify signs the transcript-hash payload per RFC 8446
// §4.4.3 with the server's ECDSA P-256 / SHA-256 private key. The output is
// the DER-encoded ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) that
// goes into the CertificateVerify handshake message's signature field; the
// surrounding wire format (algorithm code + length prefix) is the
// responsibility of the message serializer, not this package.
//
// ecdsa.SignASN1 hashes-then-signs internally? No — it signs a pre-computed
// digest. RFC 8446 §4.2.3 specifies SHA-256 as the hash for sig scheme
// 0x0403, so we hash here.
func (s *ServerIdentity) signCertificateVerify(transcriptHash []byte) ([]byte, error) {
	digest := sha256.Sum256(certificateVerifySignInput(transcriptHash))
	return ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
}
