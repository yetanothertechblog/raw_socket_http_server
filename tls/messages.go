package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TLS 1.3 handshake-message wire format (RFC 8446 §4).
//
// This file owns serialization and parsing only — it has no opinion on what
// the handshake state machine does with a parsed ClientHello or what goes
// into a ServerHello. Validation that's intrinsic to the wire format (length
// prefixes consistent, no trailing junk, no truncation) lives here; policy
// checks like "is x25519 actually offered" live in the state machine.
//
// Every handshake message has a 4-byte header (1-byte type + 3-byte length)
// followed by a body. The body layouts vary per type and are documented at
// each marshal/parse function.

const (
	// Handshake message types (RFC 8446 §B.3).
	handshakeTypeClientHello         uint8 = 1
	handshakeTypeServerHello         uint8 = 2
	handshakeTypeEncryptedExtensions uint8 = 8
	handshakeTypeCertificate         uint8 = 11
	handshakeTypeCertificateVerify   uint8 = 15
	handshakeTypeFinished            uint8 = 20

	handshakeHeaderLen = 4

	// Extension types (RFC 8446 §B.3.1). We only name the five we touch.
	extTypeServerName          uint16 = 0
	extTypeSupportedGroups     uint16 = 10
	extTypeSignatureAlgorithms uint16 = 13
	extTypeSupportedVersions   uint16 = 43
	extTypeKeyShare            uint16 = 51

	// Wire constants we negotiate.
	tls13Version uint16 = 0x0304
	tls12Version uint16 = 0x0303

	// The single curve, signature scheme, and cipher suite we support.
	// Anything else from the client gets rejected by the state machine.
	namedGroupX25519           uint16 = 0x001D
	sigSchemeECDSAP256SHA256   uint16 = 0x0403
	cipherTLSAES128GCMSHA256   uint16 = 0x1301

	// SNI name_type for host_name (RFC 6066 §3).
	sniHostName uint8 = 0
)

var (
	errMessageTruncated   = errors.New("tls: handshake message truncated")
	errTrailingBytes      = errors.New("tls: trailing bytes after handshake message")
	errBadLengthPrefix    = errors.New("tls: malformed length prefix")
	errDuplicateExtension = errors.New("tls: duplicate extension")
)

// keyShareEntry is one (group, key_exchange) pair from a KeyShare extension.
type keyShareEntry struct {
	group       uint16
	keyExchange []byte
}

// clientHello holds the fields of a parsed ClientHello that the state machine
// needs. Fields we don't use (legacy_compression_methods, extensions we
// neither read nor echo) are validated for shape but otherwise dropped.
type clientHello struct {
	legacyVersion   uint16
	random          [32]byte
	legacySessionID []byte
	cipherSuites    []uint16

	serverName          string // empty if no SNI host_name was sent
	supportedVersions   []uint16
	supportedGroups     []uint16
	signatureAlgorithms []uint16
	keyShares           []keyShareEntry
}

// findKeyShare returns the key_exchange bytes for `group`, or nil if absent.
func (c *clientHello) findKeyShare(group uint16) []byte {
	for _, ks := range c.keyShares {
		if ks.group == group {
			return ks.keyExchange
		}
	}
	return nil
}

// parseHandshake splits a handshake message buffer into (type, body). Used
// when a record has been decrypted/assembled and the caller needs to dispatch
// on type before calling the appropriate body parser.
func parseHandshake(msg []byte) (typ uint8, body []byte, err error) {
	if len(msg) < handshakeHeaderLen {
		return 0, nil, errMessageTruncated
	}
	typ = msg[0]
	bodyLen := uint32(msg[1])<<16 | uint32(msg[2])<<8 | uint32(msg[3])
	if int(bodyLen) != len(msg)-handshakeHeaderLen {
		return 0, nil, fmt.Errorf("%w: header says %d, have %d", errBadLengthPrefix, bodyLen, len(msg)-handshakeHeaderLen)
	}
	return typ, msg[handshakeHeaderLen:], nil
}

// marshalHandshake prepends the 4-byte handshake header (1-byte type, 3-byte
// big-endian length) to body and returns the full wire bytes.
func marshalHandshake(typ uint8, body []byte) []byte {
	if len(body) > 0xFFFFFF {
		// 24-bit length field. We never produce anything close to this
		// (cert is the largest we send and is well under 64 KiB).
		panic("tls: handshake body exceeds 24-bit length field")
	}
	out := make([]byte, handshakeHeaderLen+len(body))
	out[0] = typ
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[handshakeHeaderLen:], body)
	return out
}

// ----- cursor: a tiny read helper for parsers. -------------------------------

// cursor consumes a byte buffer left-to-right. Every read advances pos and
// returns errMessageTruncated if the buffer doesn't have enough bytes.
type cursor struct {
	data []byte
	pos  int
}

func (c *cursor) remaining() int { return len(c.data) - c.pos }

func (c *cursor) readU8() (uint8, error) {
	if c.remaining() < 1 {
		return 0, errMessageTruncated
	}
	v := c.data[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) readU16() (uint16, error) {
	if c.remaining() < 2 {
		return 0, errMessageTruncated
	}
	v := binary.BigEndian.Uint16(c.data[c.pos:])
	c.pos += 2
	return v, nil
}

func (c *cursor) readBytes(n int) ([]byte, error) {
	if c.remaining() < n {
		return nil, errMessageTruncated
	}
	v := c.data[c.pos : c.pos+n]
	c.pos += n
	return v, nil
}

// readVector reads a u8- or u16-length-prefixed vector and returns its body.
// `lenBytes` must be 1 or 2.
func (c *cursor) readVector(lenBytes int) ([]byte, error) {
	var n int
	switch lenBytes {
	case 1:
		v, err := c.readU8()
		if err != nil {
			return nil, err
		}
		n = int(v)
	case 2:
		v, err := c.readU16()
		if err != nil {
			return nil, err
		}
		n = int(v)
	default:
		panic("readVector: lenBytes must be 1 or 2")
	}
	return c.readBytes(n)
}

// ----- ClientHello parser ----------------------------------------------------

// parseClientHello consumes a ClientHello message body (no 4-byte handshake
// header). All length fields must be consistent and there must be no trailing
// bytes after the extensions block.
//
// Per RFC 8446 §4.1.2:
//
//	struct {
//	    ProtocolVersion legacy_version = 0x0303;     // 2 bytes
//	    Random random;                                // 32 bytes
//	    opaque legacy_session_id<0..32>;              // 1-byte length
//	    CipherSuite cipher_suites<2..2^16-2>;         // 2-byte length, entries are u16
//	    opaque legacy_compression_methods<1..2^8-1>;  // 1-byte length
//	    Extension extensions<8..2^16-1>;              // 2-byte length
//	} ClientHello;
func parseClientHello(body []byte) (*clientHello, error) {
	c := &cursor{data: body}
	out := &clientHello{}

	v, err := c.readU16()
	if err != nil {
		return nil, fmt.Errorf("legacy_version: %w", err)
	}
	out.legacyVersion = v

	rand, err := c.readBytes(32)
	if err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	copy(out.random[:], rand)

	sid, err := c.readVector(1)
	if err != nil {
		return nil, fmt.Errorf("legacy_session_id: %w", err)
	}
	if len(sid) > 32 {
		return nil, fmt.Errorf("legacy_session_id too long: %d > 32", len(sid))
	}
	out.legacySessionID = append([]byte(nil), sid...)

	cs, err := c.readVector(2)
	if err != nil {
		return nil, fmt.Errorf("cipher_suites: %w", err)
	}
	if len(cs)%2 != 0 {
		return nil, fmt.Errorf("cipher_suites length %d not a multiple of 2", len(cs))
	}
	out.cipherSuites = make([]uint16, len(cs)/2)
	for i := range out.cipherSuites {
		out.cipherSuites[i] = binary.BigEndian.Uint16(cs[i*2:])
	}

	// legacy_compression_methods: must contain exactly the null compression
	// method (0x00) for TLS 1.3 (RFC 8446 §4.1.2). We don't store it.
	comp, err := c.readVector(1)
	if err != nil {
		return nil, fmt.Errorf("legacy_compression_methods: %w", err)
	}
	if len(comp) != 1 || comp[0] != 0 {
		return nil, fmt.Errorf("legacy_compression_methods must be {0}, got %x", comp)
	}

	exts, err := c.readVector(2)
	if err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d unconsumed bytes", errTrailingBytes, c.remaining())
	}

	if err := parseClientHelloExtensions(exts, out); err != nil {
		return nil, err
	}
	return out, nil
}

// parseClientHelloExtensions walks the extensions vector and fills the
// fields of out that we care about. Unknown extensions are silently
// ignored — that's required of an extensible protocol.
func parseClientHelloExtensions(exts []byte, out *clientHello) error {
	c := &cursor{data: exts}
	seen := map[uint16]bool{}

	for c.remaining() > 0 {
		extType, err := c.readU16()
		if err != nil {
			return fmt.Errorf("extension type: %w", err)
		}
		extData, err := c.readVector(2)
		if err != nil {
			return fmt.Errorf("extension 0x%04x data: %w", extType, err)
		}
		if seen[extType] {
			return fmt.Errorf("%w: 0x%04x", errDuplicateExtension, extType)
		}
		seen[extType] = true

		switch extType {
		case extTypeServerName:
			name, err := parseServerNameExtension(extData)
			if err != nil {
				return fmt.Errorf("server_name: %w", err)
			}
			out.serverName = name
		case extTypeSupportedVersions:
			vers, err := parseSupportedVersionsExtension(extData)
			if err != nil {
				return fmt.Errorf("supported_versions: %w", err)
			}
			out.supportedVersions = vers
		case extTypeSupportedGroups:
			groups, err := parseU16Vector(extData, 2)
			if err != nil {
				return fmt.Errorf("supported_groups: %w", err)
			}
			out.supportedGroups = groups
		case extTypeSignatureAlgorithms:
			schemes, err := parseU16Vector(extData, 2)
			if err != nil {
				return fmt.Errorf("signature_algorithms: %w", err)
			}
			out.signatureAlgorithms = schemes
		case extTypeKeyShare:
			ks, err := parseClientKeyShareExtension(extData)
			if err != nil {
				return fmt.Errorf("key_share: %w", err)
			}
			out.keyShares = ks
		}
	}
	return nil
}

// parseServerNameExtension extracts the first host_name SNI entry (RFC 6066
// §3). Other name types and additional entries are ignored, which matches
// what every other TLS server does in practice.
func parseServerNameExtension(data []byte) (string, error) {
	c := &cursor{data: data}
	list, err := c.readVector(2)
	if err != nil {
		return "", fmt.Errorf("server_name_list: %w", err)
	}
	if c.remaining() != 0 {
		return "", fmt.Errorf("%w in server_name", errTrailingBytes)
	}
	lc := &cursor{data: list}
	for lc.remaining() > 0 {
		nameType, err := lc.readU8()
		if err != nil {
			return "", err
		}
		hostName, err := lc.readVector(2)
		if err != nil {
			return "", err
		}
		if nameType == sniHostName {
			return string(hostName), nil
		}
	}
	return "", nil
}

// parseSupportedVersionsExtension parses the ClientHello variant: a 1-byte-
// length-prefixed vector of u16 versions (RFC 8446 §4.2.1).
func parseSupportedVersionsExtension(data []byte) ([]uint16, error) {
	c := &cursor{data: data}
	body, err := c.readVector(1)
	if err != nil {
		return nil, fmt.Errorf("versions vector: %w", err)
	}
	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w in supported_versions", errTrailingBytes)
	}
	return parseU16Vector(body, 0) // already unwrapped, lenBytes=0 means "no length, raw"
}

// parseU16Vector parses a flat sequence of u16s. If lenBytes > 0, the input
// has a length prefix of that size; if lenBytes == 0, `data` is the unwrapped
// payload.
func parseU16Vector(data []byte, lenBytes int) ([]uint16, error) {
	body := data
	if lenBytes > 0 {
		c := &cursor{data: data}
		v, err := c.readVector(lenBytes)
		if err != nil {
			return nil, err
		}
		if c.remaining() != 0 {
			return nil, fmt.Errorf("%w in u16 vector", errTrailingBytes)
		}
		body = v
	}
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("u16 vector length %d not a multiple of 2", len(body))
	}
	out := make([]uint16, len(body)/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(body[i*2:])
	}
	return out, nil
}

// parseClientKeyShareExtension parses the ClientHello variant: a 2-byte-
// length-prefixed list of KeyShareEntry (RFC 8446 §4.2.8).
//
//	struct {
//	    NamedGroup group;
//	    opaque key_exchange<1..2^16-1>;
//	} KeyShareEntry;
func parseClientKeyShareExtension(data []byte) ([]keyShareEntry, error) {
	c := &cursor{data: data}
	list, err := c.readVector(2)
	if err != nil {
		return nil, fmt.Errorf("client_shares: %w", err)
	}
	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w in key_share", errTrailingBytes)
	}
	lc := &cursor{data: list}
	var out []keyShareEntry
	for lc.remaining() > 0 {
		group, err := lc.readU16()
		if err != nil {
			return nil, err
		}
		ke, err := lc.readVector(2)
		if err != nil {
			return nil, err
		}
		out = append(out, keyShareEntry{group: group, keyExchange: append([]byte(nil), ke...)})
	}
	return out, nil
}

// ----- Outgoing message marshalers -------------------------------------------

// marshalServerHello builds a ServerHello body (no handshake header).
//
//	struct {
//	    ProtocolVersion legacy_version = 0x0303;
//	    Random random;
//	    opaque legacy_session_id_echo<0..32>;
//	    CipherSuite cipher_suite;
//	    uint8 legacy_compression_method = 0;
//	    Extension extensions<6..2^16-1>;
//	} ServerHello;
//
// We always include exactly two extensions: supported_versions (selected =
// 0x0304) and key_share (server's x25519 public).
func marshalServerHello(random [32]byte, sessionIDEcho []byte, serverPub [32]byte) []byte {
	out := make([]byte, 0, 128)
	out = binary.BigEndian.AppendUint16(out, tls12Version) // legacy_version
	out = append(out, random[:]...)
	out = appendU8Vector(out, sessionIDEcho)
	out = binary.BigEndian.AppendUint16(out, cipherTLSAES128GCMSHA256)
	out = append(out, 0) // legacy_compression_method = null

	// Extensions block.
	exts := make([]byte, 0, 64)
	exts = appendServerSupportedVersionsExtension(exts)
	exts = appendServerKeyShareExtension(exts, serverPub)
	out = appendU16Vector(out, exts)
	return out
}

// appendServerSupportedVersionsExtension writes the ServerHello variant of
// supported_versions: a single u16 (the selected version).
func appendServerSupportedVersionsExtension(buf []byte) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, tls13Version)
	return appendExtension(buf, extTypeSupportedVersions, body)
}

// appendServerKeyShareExtension writes the ServerHello variant of key_share:
// a single KeyShareEntry (no list-length prefix).
func appendServerKeyShareExtension(buf []byte, serverPub [32]byte) []byte {
	body := make([]byte, 0, 4+32)
	body = binary.BigEndian.AppendUint16(body, namedGroupX25519)
	body = appendU16Vector(body, serverPub[:])
	return appendExtension(buf, extTypeKeyShare, body)
}

// marshalEncryptedExtensions builds an EncryptedExtensions body. We send no
// extensions at all — every extension we'd put here is optional and we don't
// negotiate any of them.
//
//	struct {
//	    Extension extensions<0..2^16-1>;
//	} EncryptedExtensions;
func marshalEncryptedExtensions() []byte {
	return []byte{0x00, 0x00} // empty extensions vector
}

// marshalCertificate builds a Certificate body containing exactly one cert
// with no per-cert extensions and no certificate_request_context.
//
//	struct {
//	    opaque certificate_request_context<0..255>;
//	    CertificateEntry certificate_list<0..2^24-1>;
//	} Certificate;
//
//	struct {
//	    opaque cert_data<1..2^24-1>;
//	    Extension extensions<0..2^16-1>;
//	} CertificateEntry;
func marshalCertificate(certDER []byte) []byte {
	// Build certificate_list body first.
	entry := make([]byte, 0, 3+len(certDER)+2)
	entry = appendU24Vector(entry, certDER)
	entry = append(entry, 0x00, 0x00) // empty per-cert extensions

	out := make([]byte, 0, 1+3+len(entry))
	out = append(out, 0x00) // empty certificate_request_context
	out = appendU24Vector(out, entry)
	return out
}

// marshalCertificateVerify builds a CertificateVerify body (RFC 8446 §4.4.3):
//
//	struct {
//	    SignatureScheme algorithm;
//	    opaque signature<0..2^16-1>;
//	} CertificateVerify;
func marshalCertificateVerify(sigScheme uint16, signature []byte) []byte {
	out := make([]byte, 0, 2+2+len(signature))
	out = binary.BigEndian.AppendUint16(out, sigScheme)
	out = appendU16Vector(out, signature)
	return out
}

// marshalFinished builds a Finished body, which is just the verify_data.
//
//	struct {
//	    opaque verify_data[Hash.length];
//	} Finished;
func marshalFinished(verifyData []byte) []byte {
	return append([]byte(nil), verifyData...)
}

// ----- small wire helpers -----------------------------------------------------

// appendExtension appends an Extension struct: u16 type || u16-length-prefixed body.
func appendExtension(buf []byte, extType uint16, body []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, extType)
	return appendU16Vector(buf, body)
}

func appendU8Vector(buf, body []byte) []byte {
	if len(body) > 0xFF {
		panic("tls: u8 vector body too long")
	}
	buf = append(buf, byte(len(body)))
	return append(buf, body...)
}

func appendU16Vector(buf, body []byte) []byte {
	if len(body) > 0xFFFF {
		panic("tls: u16 vector body too long")
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(body)))
	return append(buf, body...)
}

func appendU24Vector(buf, body []byte) []byte {
	if len(body) > 0xFFFFFF {
		panic("tls: u24 vector body too long")
	}
	buf = append(buf, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(buf, body...)
}
