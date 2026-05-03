package tls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// TLS 1.3 key schedule (RFC 8446 §7.1).
//
// We support exactly one cipher suite — TLS_AES_128_GCM_SHA256 — so the hash
// is always SHA-256 and the AEAD is always AES-128-GCM. That fixes:
//
//	hashLen = 32   // SHA-256 output / Hash.length
//	keyLen  = 16   // AES-128 key
//	ivLen   = 12   // GCM nonce (also TLS 1.3's static IV length)
const (
	hashLen = sha256.Size
	keyLen  = 16
	ivLen   = 12
)

// hkdfExpandLabel implements TLS 1.3's labeled HKDF-Expand (RFC 8446 §7.1):
//
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
//	HkdfLabel = struct {
//	    uint16 length = Length;
//	    opaque label<7..255>   = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	}
//
// The "tls13 " prefix domain-separates this HKDF use from older TLS versions
// so the same secret can never produce colliding outputs across protocols.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	info := buildHkdfLabel(label, context, length)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		// hkdf.Expand only errors when length > 255*HashLen. Our largest
		// requested length is hashLen (32), so this is unreachable.
		panic("tls: hkdfExpandLabel: " + err.Error())
	}
	return out
}

// buildHkdfLabel assembles the HkdfLabel struct that hkdfExpandLabel feeds to
// HKDF-Expand. Factored out so tests can pin its byte layout exactly without
// having to invert HKDF.
func buildHkdfLabel(label string, context []byte, length int) []byte {
	full := "tls13 " + label
	out := make([]byte, 0, 2+1+len(full)+1+len(context))
	out = binary.BigEndian.AppendUint16(out, uint16(length))
	out = append(out, byte(len(full)))
	out = append(out, full...)
	out = append(out, byte(len(context)))
	out = append(out, context...)
	return out
}

// deriveSecret runs HKDF-Expand-Label with Hash(messages) as the context and
// the hash output length as the requested length:
//
//	Derive-Secret(Secret, Label, Messages) =
//	    HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
//
// The transcript hash is passed in pre-computed; this package never tracks
// the running handshake transcript itself.
func deriveSecret(secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(secret, label, transcriptHash, hashLen)
}

// hkdfExtract wraps the stdlib's HKDF-Extract for our suite's hash. Per
// RFC 5869, a nil/empty salt is equivalent to a HashLen-byte string of zeros,
// which is what TLS 1.3's "0" inputs to the schedule mean.
func hkdfExtract(salt, ikm []byte) []byte {
	out, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic("tls: hkdfExtract: " + err.Error())
	}
	return out
}

// keySchedule materializes the secrets of a TLS 1.3 1-RTT handshake.
//
// The schedule is split across two calls because the application-traffic
// secrets depend on the transcript hash captured *after* server Finished —
// which we don't know when we begin deriving handshake-traffic keys.
type keySchedule struct {
	earlySecret     []byte
	handshakeSecret []byte
	masterSecret    []byte // populated only after SetServerFinishedTranscript

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte

	clientApplicationTrafficSecret []byte // populated only after SetServerFinishedTranscript
	serverApplicationTrafficSecret []byte // populated only after SetServerFinishedTranscript
}

// newKeySchedule runs the schedule through the handshake-traffic secrets:
//
//	0       -> Extract -> Early
//	derived <- DeriveSecret(Early, "derived", "")
//	ECDHE   -> Extract(salt=derived) -> Handshake
//	          DeriveSecret(Handshake, "c hs traffic", H(CH..SH))
//	          DeriveSecret(Handshake, "s hs traffic", H(CH..SH))
//
// transcriptCHSH must be SHA256(ClientHello || ServerHello).
func newKeySchedule(ecdheShared, transcriptCHSH []byte) *keySchedule {
	zeros := make([]byte, hashLen)
	emptyHash := sha256.Sum256(nil)

	early := hkdfExtract(nil, zeros) // PSK = 0 (no resumption)
	derivedEarly := deriveSecret(early, "derived", emptyHash[:])
	handshake := hkdfExtract(derivedEarly, ecdheShared)

	return &keySchedule{
		earlySecret:                  early,
		handshakeSecret:              handshake,
		clientHandshakeTrafficSecret: deriveSecret(handshake, "c hs traffic", transcriptCHSH),
		serverHandshakeTrafficSecret: deriveSecret(handshake, "s hs traffic", transcriptCHSH),
	}
}

// SetServerFinishedTranscript completes the schedule:
//
//	derived <- DeriveSecret(Handshake, "derived", "")
//	0       -> Extract(salt=derived) -> Master
//	          DeriveSecret(Master, "c ap traffic", H(CH..ServerFinished))
//	          DeriveSecret(Master, "s ap traffic", H(CH..ServerFinished))
//
// transcriptCHSF must be SHA256(ClientHello..server Finished).
func (k *keySchedule) SetServerFinishedTranscript(transcriptCHSF []byte) {
	zeros := make([]byte, hashLen)
	emptyHash := sha256.Sum256(nil)

	derivedHandshake := deriveSecret(k.handshakeSecret, "derived", emptyHash[:])
	k.masterSecret = hkdfExtract(derivedHandshake, zeros)

	k.clientApplicationTrafficSecret = deriveSecret(k.masterSecret, "c ap traffic", transcriptCHSF)
	k.serverApplicationTrafficSecret = deriveSecret(k.masterSecret, "s ap traffic", transcriptCHSF)
}

// trafficKeyAndIV derives the per-direction AEAD key and static IV from a
// traffic secret (RFC 8446 §7.3). The static IV is XOR'd with the per-record
// sequence number to form each AEAD nonce.
func trafficKeyAndIV(trafficSecret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(trafficSecret, "key", nil, keyLen)
	iv = hkdfExpandLabel(trafficSecret, "iv", nil, ivLen)
	return
}

// finishedKey derives the HMAC key used to compute the Finished message
// (RFC 8446 §4.4.4):
//
//	finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
//	verify_data  = HMAC(finished_key, Transcript-Hash(handshake_messages))
func finishedKey(trafficSecret []byte) []byte {
	return hkdfExpandLabel(trafficSecret, "finished", nil, hashLen)
}

// verifyData computes the Finished verify_data field (RFC 8446 §4.4.4):
//
//	verify_data = HMAC(finished_key(traffic_secret), Transcript-Hash(...))
//
// `transcriptHash` is the SHA-256 transcript through the message immediately
// before the Finished being computed (server: through CertificateVerify;
// client: through server Finished).
func verifyData(trafficSecret, transcriptHash []byte) []byte {
	mac := hmac.New(sha256.New, finishedKey(trafficSecret))
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}
