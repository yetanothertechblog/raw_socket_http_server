package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TLS 1.3 record layer (RFC 8446 §5).
//
// A record is a 5-byte header  (type, legacy_version, length)  followed by a
// fragment of up to 2^14 plaintext bytes — or up to 2^14 + 256 ciphertext
// bytes when AEAD is active. Once handshake-traffic keys are derived, every
// record's outer type field is fixed at application_data (0x17); the *real*
// content type is appended to the plaintext before AEAD seal, hiding it
// from any passive observer.
//
// This file owns three concerns:
//   1. Reading and writing the 5-byte record header from/to an io.ReadWriter
//      (no decryption — works for both plaintext and ciphertext records).
//   2. AEAD seal/open with the per-record nonce derivation
//      (nonce = pad_left(seq, 12 bytes) XOR static_iv).
//   3. Stripping trailing zero padding from a decrypted inner plaintext to
//      recover the real content type byte.
//
// What it does NOT own: the handshake state machine that decides which
// epoch's keys are active, fragmentation of oversized handshake messages,
// or filtering of the legacy ChangeCipherSpec record (the state machine
// silently drops those for compatibility).

// ContentType values per RFC 8446 §B.1. We export them as package-private
// constants for use by the handshake serializer.
const (
	contentTypeChangeCipherSpec uint8 = 20
	contentTypeAlert            uint8 = 21
	contentTypeHandshake        uint8 = 22
	contentTypeApplicationData  uint8 = 23
)

// Wire framing constants.
const (
	// legacyRecordVersion is the value placed in (and required-on-receive,
	// modulo a few exceptions for the very first ClientHello) the
	// ProtocolVersion field. RFC 8446 §5.1: "the legacy_record_version
	// field is deprecated and MUST be ignored for all purposes". We set
	// it to TLS 1.2's 0x0303 on send for middlebox compatibility.
	legacyRecordVersion uint16 = 0x0303

	recordHeaderLen     = 5
	maxPlaintextLength  = 1 << 14       // RFC 8446 §5.1
	maxCiphertextLength = (1 << 14) + 256 // RFC 8446 §5.2 (plaintext + tag + padding budget)

	// AES-128-GCM specifics for our single supported cipher suite.
	aeadKeyLen   = 16
	aeadIVLen    = 12
	aeadOverhead = 16 // GCM auth tag
)

var (
	errRecordTooLarge      = errors.New("tls: record fragment exceeds maximum size")
	errEmptyInnerPlaintext = errors.New("tls: decrypted record has no content type byte")
	errInvalidKeyLength    = errors.New("tls: AEAD key must be 16 bytes for AES-128-GCM")
	errInvalidIVLength     = errors.New("tls: AEAD IV must be 12 bytes")
)

// readRecord reads one TLS record (header + fragment) from r. It does not
// decrypt — the caller decides, based on epoch, whether `fragment` is
// plaintext or AEAD-sealed.
//
// On a clean io.EOF before any header bytes are read, returns io.EOF
// untouched so callers can distinguish "peer closed cleanly" from "wire
// truncation". On a partial header read, returns io.ErrUnexpectedEOF.
func readRecord(r io.Reader) (header [recordHeaderLen]byte, fragment []byte, err error) {
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return header, nil, err
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > maxCiphertextLength {
		return header, nil, fmt.Errorf("%w: %d > %d", errRecordTooLarge, length, maxCiphertextLength)
	}

	fragment = make([]byte, length)
	if _, err = io.ReadFull(r, fragment); err != nil {
		return header, nil, err
	}
	return header, fragment, nil
}

// writeRecord serializes a single record to w. The caller passes the outer
// content type and the fragment bytes (already encrypted, if AEAD is in
// effect). Caller is responsible for keeping fragment ≤ maxCiphertextLength.
func writeRecord(w io.Writer, contentType uint8, fragment []byte) error {
	if len(fragment) > maxCiphertextLength {
		return fmt.Errorf("%w: %d > %d", errRecordTooLarge, len(fragment), maxCiphertextLength)
	}

	var header [recordHeaderLen]byte
	header[0] = contentType
	binary.BigEndian.PutUint16(header[1:3], legacyRecordVersion)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(fragment)))

	// Single Write call avoids the partial-write torn-record case where a
	// reader could see a header without a body. io.Writer doesn't promise
	// atomicity, but most underlying transports either deliver the whole
	// slice or none of it.
	out := make([]byte, recordHeaderLen+len(fragment))
	copy(out, header[:])
	copy(out[recordHeaderLen:], fragment)

	_, err := w.Write(out)
	return err
}

// nonceForSeq derives the per-record AEAD nonce per RFC 8446 §5.3:
//
//	nonce = pad_left(seq, 12_bytes_big_endian) XOR static_iv
//
// "pad_left" means seq occupies the trailing 8 bytes; the leading 4 bytes
// are zero before the XOR. Because seq starts at 0 and is reset on every
// rekey, every distinct (key, nonce) pair is used exactly once — which is
// what GCM needs to stay secure.
func nonceForSeq(iv [aeadIVLen]byte, seq uint64) [aeadIVLen]byte {
	var nonce [aeadIVLen]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	for i := range nonce {
		nonce[i] ^= iv[i]
	}
	return nonce
}

// recordKeys holds the AEAD context for one direction of an encrypted TLS
// connection. Each direction has its own keys, IV, and sequence counter.
//
// The sequence counter is incremented on every successful Seal or Open. A
// rekey (handshake-traffic → application-traffic, or post-handshake key
// update) is modeled by replacing the *recordKeys with a fresh one — never
// by mutating the seq back to zero in place.
type recordKeys struct {
	aead cipher.AEAD
	iv   [aeadIVLen]byte
	seq  uint64
}

// newRecordKeys constructs a recordKeys for AES-128-GCM from a 16-byte key
// and 12-byte IV. The AEAD instance is freshly allocated; passing the same
// key to two newRecordKeys calls produces two independent ciphers with their
// own sequence counters (one for each direction, e.g.).
func newRecordKeys(key, iv []byte) (*recordKeys, error) {
	if len(key) != aeadKeyLen {
		return nil, fmt.Errorf("%w: got %d", errInvalidKeyLength, len(key))
	}
	if len(iv) != aeadIVLen {
		return nil, fmt.Errorf("%w: got %d", errInvalidIVLength, len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	r := &recordKeys{aead: aead}
	copy(r.iv[:], iv)
	return r, nil
}

// Seal builds a complete TLSCiphertext (5-byte outer header + AEAD output)
// containing the given inner content type and plaintext. The inner plaintext
// passed to AEAD is constructed as
//
//	plaintext || innerType || (no padding)
//
// per RFC 8446 §5.2, with the outer record header used as additional data
// so any tampering with header bytes is caught by the GCM tag check on
// open. We deliberately add no zero padding — padding only buys traffic-
// analysis resistance, which is out of our scope.
//
// Increments the sequence counter on success.
func (r *recordKeys) Seal(innerType uint8, plaintext []byte) ([]byte, error) {
	// Inner plaintext: real bytes followed by the real content type.
	inner := make([]byte, len(plaintext)+1)
	copy(inner, plaintext)
	inner[len(plaintext)] = innerType

	// Outer record header. Length field covers the AEAD ciphertext, which
	// is inner_len + GCM tag.
	ciphertextLen := len(inner) + r.aead.Overhead()
	if ciphertextLen > maxCiphertextLength {
		return nil, fmt.Errorf("%w: ciphertext would be %d bytes", errRecordTooLarge, ciphertextLen)
	}

	var header [recordHeaderLen]byte
	header[0] = contentTypeApplicationData
	binary.BigEndian.PutUint16(header[1:3], legacyRecordVersion)
	binary.BigEndian.PutUint16(header[3:5], uint16(ciphertextLen))

	nonce := nonceForSeq(r.iv, r.seq)
	sealed := r.aead.Seal(nil, nonce[:], inner, header[:])

	out := make([]byte, recordHeaderLen+len(sealed))
	copy(out, header[:])
	copy(out[recordHeaderLen:], sealed)

	r.seq++
	return out, nil
}

// Open verifies the AEAD tag on a record fragment and returns the recovered
// inner content type and plaintext, with any trailing zero padding stripped.
//
// `header` is the 5-byte outer header that was on the wire (used as AAD).
// `ciphertext` is the record body bytes that followed it.
//
// The padding-stripping convention is: scan from the end of the decrypted
// inner buffer backwards through zero bytes; the first non-zero byte is the
// real content type. This is well-defined because the four legal content
// types (20, 21, 22, 23) are all non-zero, so a real type byte is never
// confused with padding.
//
// Increments the sequence counter on a successful Open. A failed Open does
// not advance — the caller should typically tear down the connection.
func (r *recordKeys) Open(header [recordHeaderLen]byte, ciphertext []byte) (innerType uint8, plaintext []byte, err error) {
	nonce := nonceForSeq(r.iv, r.seq)
	inner, err := r.aead.Open(nil, nonce[:], ciphertext, header[:])
	if err != nil {
		return 0, nil, err
	}

	// Walk back over zero padding to find the real content-type byte.
	end := len(inner) - 1
	for end >= 0 && inner[end] == 0 {
		end--
	}
	if end < 0 {
		return 0, nil, errEmptyInnerPlaintext
	}

	innerType = inner[end]
	plaintext = inner[:end]
	r.seq++
	return innerType, plaintext, nil
}
