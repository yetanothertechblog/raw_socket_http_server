package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// ----- byte-builder helpers (test-only) --------------------------------------

// buildExt assembles one extension on the wire: u16 type + u16-length body.
func buildExt(t uint16, body []byte) []byte {
	out := make([]byte, 0, 4+len(body))
	out = binary.BigEndian.AppendUint16(out, t)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// buildSupportedVersionsClient: u8-length-prefixed list of u16 versions.
func buildSupportedVersionsClient(versions ...uint16) []byte {
	body := make([]byte, 1+2*len(versions))
	body[0] = byte(2 * len(versions))
	for i, v := range versions {
		binary.BigEndian.PutUint16(body[1+2*i:], v)
	}
	return body
}

// buildU16ListExt: u16-length-prefixed list of u16s, used for
// supported_groups and signature_algorithms.
func buildU16ListExt(values ...uint16) []byte {
	body := make([]byte, 2+2*len(values))
	binary.BigEndian.PutUint16(body, uint16(2*len(values)))
	for i, v := range values {
		binary.BigEndian.PutUint16(body[2+2*i:], v)
	}
	return body
}

// buildClientKeyShare: u16-list-length, then entries of (group u16, key u16-len-prefixed).
func buildClientKeyShare(entries []keyShareEntry) []byte {
	var inner []byte
	for _, e := range entries {
		inner = binary.BigEndian.AppendUint16(inner, e.group)
		inner = binary.BigEndian.AppendUint16(inner, uint16(len(e.keyExchange)))
		inner = append(inner, e.keyExchange...)
	}
	out := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(out, uint16(len(inner)))
	copy(out[2:], inner)
	return out
}

// buildSNI: server_name_list with one host_name entry.
func buildSNI(host string) []byte {
	// inner entry: name_type (1 byte) + host_name<2..2^16-1>
	entry := make([]byte, 0, 3+len(host))
	entry = append(entry, sniHostName)
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(host)))
	entry = append(entry, host...)
	out := make([]byte, 2+len(entry))
	binary.BigEndian.PutUint16(out, uint16(len(entry)))
	copy(out[2:], entry)
	return out
}

// buildClientHelloBody assembles a valid ClientHello body with the supplied
// extensions block.
func buildClientHelloBody(random [32]byte, sessionID []byte, suites []uint16, exts []byte) []byte {
	out := make([]byte, 0, 100+len(exts))
	out = binary.BigEndian.AppendUint16(out, tls12Version)
	out = append(out, random[:]...)
	out = append(out, byte(len(sessionID)))
	out = append(out, sessionID...)
	out = binary.BigEndian.AppendUint16(out, uint16(2*len(suites)))
	for _, s := range suites {
		out = binary.BigEndian.AppendUint16(out, s)
	}
	out = append(out, 1, 0) // compression: {null}
	out = binary.BigEndian.AppendUint16(out, uint16(len(exts)))
	out = append(out, exts...)
	return out
}

// goodHelloKey is a fixed 32-byte "client x25519 public" used in many tests.
// Real x25519 publics aren't structured, so any 32-byte string is valid input
// to the parser.
var goodHelloKey = bytes.Repeat([]byte{0x42}, 32)

// makeGoodClientHello returns a ClientHello body that parses cleanly with all
// fields populated. Tests that need to perturb one field copy this and edit.
func makeGoodClientHello() ([]byte, [32]byte) {
	var random [32]byte
	for i := range random {
		random[i] = byte(i)
	}
	exts := bytes.Join([][]byte{
		buildExt(extTypeServerName, buildSNI("localhost")),
		buildExt(extTypeSupportedVersions, buildSupportedVersionsClient(tls13Version)),
		buildExt(extTypeSupportedGroups, buildU16ListExt(namedGroupX25519)),
		buildExt(extTypeSignatureAlgorithms, buildU16ListExt(sigSchemeEd25519)),
		buildExt(extTypeKeyShare, buildClientKeyShare([]keyShareEntry{
			{group: namedGroupX25519, keyExchange: goodHelloKey},
		})),
	}, nil)
	return buildClientHelloBody(random, []byte{0xAA, 0xBB}, []uint16{cipherTLSAES128GCMSHA256}, exts), random
}

// ----- Handshake header ------------------------------------------------------

func TestMarshalHandshake_HeaderLayout(t *testing.T) {
	body := []byte{1, 2, 3, 4, 5}
	out := marshalHandshake(handshakeTypeServerHello, body)

	if len(out) != 4+len(body) {
		t.Fatalf("len = %d, want %d", len(out), 4+len(body))
	}
	if out[0] != handshakeTypeServerHello {
		t.Errorf("type = %d, want %d", out[0], handshakeTypeServerHello)
	}
	gotLen := uint32(out[1])<<16 | uint32(out[2])<<8 | uint32(out[3])
	if gotLen != uint32(len(body)) {
		t.Errorf("length = %d, want %d", gotLen, len(body))
	}
	if !bytes.Equal(out[4:], body) {
		t.Errorf("body = %x, want %x", out[4:], body)
	}
}

func TestParseHandshake_Roundtrip(t *testing.T) {
	body := []byte("hello world")
	wire := marshalHandshake(handshakeTypeFinished, body)

	typ, gotBody, err := parseHandshake(wire)
	if err != nil {
		t.Fatalf("parseHandshake: %v", err)
	}
	if typ != handshakeTypeFinished {
		t.Errorf("type = %d", typ)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body = %q", gotBody)
	}
}

func TestParseHandshake_RejectsTruncatedHeader(t *testing.T) {
	if _, _, err := parseHandshake([]byte{0x01, 0x00}); err == nil {
		t.Errorf("expected error on 2-byte input")
	}
}

func TestParseHandshake_RejectsInconsistentLength(t *testing.T) {
	// Header claims 5-byte body, but only 3 bytes follow.
	wire := []byte{handshakeTypeFinished, 0, 0, 5, 1, 2, 3}
	if _, _, err := parseHandshake(wire); !errors.Is(err, errBadLengthPrefix) {
		t.Errorf("expected errBadLengthPrefix, got %v", err)
	}
}

// ----- ClientHello: happy path -----------------------------------------------

func TestParseClientHello_Happy(t *testing.T) {
	body, random := makeGoodClientHello()
	hello, err := parseClientHello(body)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if hello.legacyVersion != tls12Version {
		t.Errorf("legacyVersion = %#x", hello.legacyVersion)
	}
	if hello.random != random {
		t.Errorf("random = %x, want %x", hello.random, random)
	}
	if !bytes.Equal(hello.legacySessionID, []byte{0xAA, 0xBB}) {
		t.Errorf("sessionID = %x", hello.legacySessionID)
	}
	if len(hello.cipherSuites) != 1 || hello.cipherSuites[0] != cipherTLSAES128GCMSHA256 {
		t.Errorf("cipherSuites = %v", hello.cipherSuites)
	}
	if hello.serverName != "localhost" {
		t.Errorf("serverName = %q", hello.serverName)
	}
	if len(hello.supportedVersions) != 1 || hello.supportedVersions[0] != tls13Version {
		t.Errorf("supportedVersions = %v", hello.supportedVersions)
	}
	if len(hello.supportedGroups) != 1 || hello.supportedGroups[0] != namedGroupX25519 {
		t.Errorf("supportedGroups = %v", hello.supportedGroups)
	}
	if len(hello.signatureAlgorithms) != 1 || hello.signatureAlgorithms[0] != sigSchemeEd25519 {
		t.Errorf("signatureAlgorithms = %v", hello.signatureAlgorithms)
	}
	if len(hello.keyShares) != 1 ||
		hello.keyShares[0].group != namedGroupX25519 ||
		!bytes.Equal(hello.keyShares[0].keyExchange, goodHelloKey) {
		t.Errorf("keyShares = %+v", hello.keyShares)
	}
}

func TestClientHello_FindKeyShare(t *testing.T) {
	body, _ := makeGoodClientHello()
	hello, err := parseClientHello(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := hello.findKeyShare(namedGroupX25519); !bytes.Equal(got, goodHelloKey) {
		t.Errorf("findKeyShare(x25519) = %x, want %x", got, goodHelloKey)
	}
	if got := hello.findKeyShare(0x0017); got != nil {
		t.Errorf("findKeyShare(secp256r1) = %x, want nil", got)
	}
}

// ----- ClientHello: error cases ----------------------------------------------

func TestParseClientHello_Truncated(t *testing.T) {
	body, _ := makeGoodClientHello()
	for cut := 0; cut < len(body); cut += 7 {
		if _, err := parseClientHello(body[:cut]); err == nil {
			t.Errorf("cut=%d parsed without error", cut)
		}
	}
}

func TestParseClientHello_RejectsBadCompression(t *testing.T) {
	exts := buildExt(extTypeSupportedVersions, buildSupportedVersionsClient(tls13Version))
	bad := buildClientHelloBody([32]byte{}, nil, []uint16{cipherTLSAES128GCMSHA256}, exts)
	// Find the compression byte (after 2 ver + 32 random + 1+0 sid + 2+2 suites)
	idx := 2 + 32 + 1 + 0 + 2 + 2
	if bad[idx] != 1 || bad[idx+1] != 0 {
		t.Fatalf("test setup expected {1,0} compression at %d, got {%d,%d}", idx, bad[idx], bad[idx+1])
	}
	bad[idx+1] = 1 // change compression method from null(0) to deflate(1)
	if _, err := parseClientHello(bad); err == nil {
		t.Errorf("expected error on non-null compression method")
	}
}

func TestParseClientHello_RejectsOddCipherSuites(t *testing.T) {
	// Hand-build a ClientHello where cipher_suites length = 3 (odd).
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)             // session_id len = 0
	body = append(body, 0x00, 0x03)       // cipher_suites len = 3
	body = append(body, 0x13, 0x01, 0xFF) // 3 bytes
	body = append(body, 0x01, 0x00)       // compression
	body = append(body, 0x00, 0x00)       // empty extensions
	if _, err := parseClientHello(body); err == nil {
		t.Errorf("expected error on odd-length cipher_suites")
	}
}

func TestParseClientHello_RejectsDuplicateExtension(t *testing.T) {
	exts := bytes.Join([][]byte{
		buildExt(extTypeSupportedVersions, buildSupportedVersionsClient(tls13Version)),
		buildExt(extTypeSupportedVersions, buildSupportedVersionsClient(tls13Version)),
	}, nil)
	body := buildClientHelloBody([32]byte{}, nil, []uint16{cipherTLSAES128GCMSHA256}, exts)
	if _, err := parseClientHello(body); !errors.Is(err, errDuplicateExtension) {
		t.Errorf("want errDuplicateExtension, got %v", err)
	}
}

func TestParseClientHello_RejectsTrailingBytes(t *testing.T) {
	body, _ := makeGoodClientHello()
	body = append(body, 0xFF) // junk after extensions
	if _, err := parseClientHello(body); err == nil {
		t.Errorf("expected error on trailing bytes")
	}
}

func TestParseClientHello_IgnoresUnknownExtension(t *testing.T) {
	// Same as makeGoodClientHello but with an extra unknown extension.
	random := [32]byte{}
	exts := bytes.Join([][]byte{
		buildExt(extTypeSupportedVersions, buildSupportedVersionsClient(tls13Version)),
		buildExt(0xABCD, []byte{1, 2, 3, 4}), // unknown
		buildExt(extTypeSupportedGroups, buildU16ListExt(namedGroupX25519)),
		buildExt(extTypeKeyShare, buildClientKeyShare([]keyShareEntry{
			{group: namedGroupX25519, keyExchange: goodHelloKey},
		})),
	}, nil)
	body := buildClientHelloBody(random, nil, []uint16{cipherTLSAES128GCMSHA256}, exts)
	hello, err := parseClientHello(body)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if hello.findKeyShare(namedGroupX25519) == nil {
		t.Errorf("known extensions still parsed alongside unknown ext")
	}
}

func TestParseClientHello_MultipleKeyShareEntries(t *testing.T) {
	otherKey := bytes.Repeat([]byte{0x77}, 65) // any size; we only care about x25519's
	exts := bytes.Join([][]byte{
		buildExt(extTypeSupportedVersions, buildSupportedVersionsClient(tls13Version)),
		buildExt(extTypeKeyShare, buildClientKeyShare([]keyShareEntry{
			{group: 0x0017, keyExchange: otherKey},          // secp256r1 (we don't support)
			{group: namedGroupX25519, keyExchange: goodHelloKey},
		})),
	}, nil)
	body := buildClientHelloBody([32]byte{}, nil, []uint16{cipherTLSAES128GCMSHA256}, exts)
	hello, err := parseClientHello(body)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if len(hello.keyShares) != 2 {
		t.Fatalf("keyShares len = %d, want 2", len(hello.keyShares))
	}
	if !bytes.Equal(hello.findKeyShare(namedGroupX25519), goodHelloKey) {
		t.Errorf("x25519 share not found among multiple")
	}
}

// ----- ServerHello marshal ---------------------------------------------------

func TestMarshalServerHello_Layout(t *testing.T) {
	var random [32]byte
	for i := range random {
		random[i] = byte(0x80 | i)
	}
	sessionEcho := []byte{1, 2, 3, 4}
	var serverPub [32]byte
	for i := range serverPub {
		serverPub[i] = byte(i + 1)
	}

	body := marshalServerHello(random, sessionEcho, serverPub)
	c := &cursor{data: body}

	gotVer, _ := c.readU16()
	if gotVer != tls12Version {
		t.Errorf("legacy_version = %#x, want %#x", gotVer, tls12Version)
	}
	gotRand, _ := c.readBytes(32)
	if !bytes.Equal(gotRand, random[:]) {
		t.Errorf("random mismatch")
	}
	sid, _ := c.readVector(1)
	if !bytes.Equal(sid, sessionEcho) {
		t.Errorf("session_id_echo = %x", sid)
	}
	gotCS, _ := c.readU16()
	if gotCS != cipherTLSAES128GCMSHA256 {
		t.Errorf("cipher_suite = %#x", gotCS)
	}
	comp, _ := c.readU8()
	if comp != 0 {
		t.Errorf("compression = %d", comp)
	}
	exts, _ := c.readVector(2)
	if c.remaining() != 0 {
		t.Errorf("trailing bytes after extensions")
	}

	// Walk the extensions block; we expect supported_versions then key_share.
	ec := &cursor{data: exts}
	t1, _ := ec.readU16()
	body1, _ := ec.readVector(2)
	if t1 != extTypeSupportedVersions {
		t.Errorf("ext1 type = %#x, want supported_versions", t1)
	}
	if len(body1) != 2 || binary.BigEndian.Uint16(body1) != tls13Version {
		t.Errorf("supported_versions body = %x, want 0304", body1)
	}

	t2, _ := ec.readU16()
	body2, _ := ec.readVector(2)
	if t2 != extTypeKeyShare {
		t.Errorf("ext2 type = %#x, want key_share", t2)
	}
	// key_share body: group(u16) || u16-len key
	if len(body2) != 2+2+32 {
		t.Errorf("key_share body len = %d, want %d", len(body2), 2+2+32)
	}
	if binary.BigEndian.Uint16(body2[0:2]) != namedGroupX25519 {
		t.Errorf("key_share group = %#x", binary.BigEndian.Uint16(body2[0:2]))
	}
	if binary.BigEndian.Uint16(body2[2:4]) != 32 {
		t.Errorf("key_share key length = %d, want 32", binary.BigEndian.Uint16(body2[2:4]))
	}
	if !bytes.Equal(body2[4:], serverPub[:]) {
		t.Errorf("key_share public = %x, want %x", body2[4:], serverPub)
	}

	if ec.remaining() != 0 {
		t.Errorf("unexpected extra extensions in ServerHello")
	}
}

// ----- EncryptedExtensions ---------------------------------------------------

func TestMarshalEncryptedExtensions_Empty(t *testing.T) {
	got := marshalEncryptedExtensions()
	if !bytes.Equal(got, []byte{0x00, 0x00}) {
		t.Errorf("got %x, want 0000", got)
	}
}

// ----- Certificate -----------------------------------------------------------

func TestMarshalCertificate_Layout(t *testing.T) {
	cert := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11}
	body := marshalCertificate(cert)

	if body[0] != 0x00 {
		t.Errorf("certificate_request_context length = %d, want 0", body[0])
	}
	listLen := uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3])
	// One entry: 3-byte cert len + cert + 2-byte ext len.
	wantListLen := uint32(3 + len(cert) + 2)
	if listLen != wantListLen {
		t.Errorf("list len = %d, want %d", listLen, wantListLen)
	}
	entry := body[4:]
	if len(entry) != int(listLen) {
		t.Errorf("entry len = %d, want %d", len(entry), listLen)
	}
	certLen := uint32(entry[0])<<16 | uint32(entry[1])<<8 | uint32(entry[2])
	if certLen != uint32(len(cert)) {
		t.Errorf("cert len = %d, want %d", certLen, len(cert))
	}
	if !bytes.Equal(entry[3:3+len(cert)], cert) {
		t.Errorf("cert bytes mismatch")
	}
	tail := entry[3+len(cert):]
	if !bytes.Equal(tail, []byte{0x00, 0x00}) {
		t.Errorf("per-cert extensions = %x, want 0000", tail)
	}
}

// ----- CertificateVerify -----------------------------------------------------

func TestMarshalCertificateVerify_Layout(t *testing.T) {
	sig := bytes.Repeat([]byte{0x55}, 64) // ed25519 signature size
	body := marshalCertificateVerify(sigSchemeEd25519, sig)
	if len(body) != 2+2+64 {
		t.Fatalf("len = %d, want %d", len(body), 2+2+64)
	}
	if binary.BigEndian.Uint16(body[:2]) != sigSchemeEd25519 {
		t.Errorf("scheme = %#x", binary.BigEndian.Uint16(body[:2]))
	}
	if binary.BigEndian.Uint16(body[2:4]) != 64 {
		t.Errorf("sig length = %d", binary.BigEndian.Uint16(body[2:4]))
	}
	if !bytes.Equal(body[4:], sig) {
		t.Errorf("sig bytes mismatch")
	}
}

// ----- Finished --------------------------------------------------------------

func TestMarshalFinished_IsCopy(t *testing.T) {
	verify := []byte{1, 2, 3, 4}
	body := marshalFinished(verify)
	if !bytes.Equal(body, verify) {
		t.Errorf("body = %x", body)
	}
	// Writing through the source must not mutate the marshaled output.
	verify[0] = 0xFF
	if body[0] == 0xFF {
		t.Errorf("marshalFinished returned a slice that aliases its input")
	}
}

// ----- Cursor primitives -----------------------------------------------------

func TestCursor_BasicReads(t *testing.T) {
	c := &cursor{data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}}
	if v, _ := c.readU8(); v != 0x01 {
		t.Errorf("readU8 = %#x", v)
	}
	if v, _ := c.readU16(); v != 0x0203 {
		t.Errorf("readU16 = %#x", v)
	}
	if v, _ := c.readBytes(2); !bytes.Equal(v, []byte{0x04, 0x05}) {
		t.Errorf("readBytes = %x", v)
	}
	if c.remaining() != 1 {
		t.Errorf("remaining = %d", c.remaining())
	}
}

func TestCursor_ReadVectorU8(t *testing.T) {
	c := &cursor{data: []byte{0x03, 0xAA, 0xBB, 0xCC, 0x99}}
	v, err := c.readVector(1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("vector = %x", v)
	}
	if c.remaining() != 1 || c.data[c.pos] != 0x99 {
		t.Errorf("cursor not at correct position: remaining=%d", c.remaining())
	}
}

func TestCursor_ReadVectorU16(t *testing.T) {
	c := &cursor{data: []byte{0x00, 0x02, 0xAA, 0xBB, 0xFF}}
	v, err := c.readVector(2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, []byte{0xAA, 0xBB}) {
		t.Errorf("vector = %x", v)
	}
}

func TestCursor_ReadVectorTruncated(t *testing.T) {
	// length says 5, only 2 follow
	c := &cursor{data: []byte{0x05, 0xAA, 0xBB}}
	if _, err := c.readVector(1); !errors.Is(err, errMessageTruncated) {
		t.Errorf("want errMessageTruncated, got %v", err)
	}
}

// ----- u24 helper ------------------------------------------------------------

func TestAppendU24Vector_Layout(t *testing.T) {
	body := []byte{0xAB, 0xCD}
	out := appendU24Vector(nil, body)
	if !bytes.Equal(out, []byte{0x00, 0x00, 0x02, 0xAB, 0xCD}) {
		t.Errorf("got %x", out)
	}
}
