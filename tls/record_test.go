package tls

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// --- Wire framing -----------------------------------------------------------

func TestReadRecord_ParsesHeaderAndFragment(t *testing.T) {
	// type=handshake (22), version=0x0303, length=4, fragment=DEADBEEF
	wire := []byte{
		22,
		0x03, 0x03,
		0x00, 0x04,
		0xDE, 0xAD, 0xBE, 0xEF,
	}

	header, fragment, err := readRecord(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("readRecord: %v", err)
	}
	if header[0] != contentTypeHandshake {
		t.Errorf("header[0] = %d, want %d", header[0], contentTypeHandshake)
	}
	if !bytes.Equal(fragment, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("fragment = %x", fragment)
	}
}

func TestReadRecord_CleanEOFReturnsEOF(t *testing.T) {
	// Empty input — peer closed before sending anything. Caller wants to
	// distinguish this from truncation, so we surface io.EOF unchanged.
	_, _, err := readRecord(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

func TestReadRecord_TruncatedHeaderReturnsUnexpectedEOF(t *testing.T) {
	// Three bytes — header is 5, so io.ReadFull surfaces ErrUnexpectedEOF.
	_, _, err := readRecord(bytes.NewReader([]byte{22, 0x03, 0x03}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadRecord_TruncatedFragmentReturnsUnexpectedEOF(t *testing.T) {
	// Header announces 4 bytes, only 2 follow.
	wire := []byte{22, 0x03, 0x03, 0x00, 0x04, 0xAA, 0xBB}
	_, _, err := readRecord(bytes.NewReader(wire))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadRecord_RejectsOversizeLength(t *testing.T) {
	// Length field declares > maxCiphertextLength.
	wire := []byte{22, 0x03, 0x03, 0xFF, 0xFF}
	_, _, err := readRecord(bytes.NewReader(wire))
	if !errors.Is(err, errRecordTooLarge) {
		t.Errorf("err = %v, want errRecordTooLarge", err)
	}
}

func TestWriteRecord_BytesOnWire(t *testing.T) {
	var buf bytes.Buffer
	frag := []byte{0xCA, 0xFE}
	if err := writeRecord(&buf, contentTypeHandshake, frag); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}

	want := []byte{
		22,         // contentTypeHandshake
		0x03, 0x03, // legacy_record_version
		0x00, 0x02, // length
		0xCA, 0xFE,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("on-wire = %x, want %x", buf.Bytes(), want)
	}
}

func TestWriteRecord_RejectsOversizeFragment(t *testing.T) {
	// One byte too big.
	frag := make([]byte, maxCiphertextLength+1)
	err := writeRecord(io.Discard, contentTypeApplicationData, frag)
	if !errors.Is(err, errRecordTooLarge) {
		t.Errorf("err = %v, want errRecordTooLarge", err)
	}
}

// TestRecord_RoundtripWriteRead pushes a few records through a single buffer
// in both directions to confirm read and write agree on framing.
func TestRecord_RoundtripWriteRead(t *testing.T) {
	var buf bytes.Buffer
	cases := [][]byte{
		nil,
		{0x01},
		bytes.Repeat([]byte{0xAB}, 100),
		bytes.Repeat([]byte{0xCD}, maxPlaintextLength), // largest plaintext-record fragment
	}
	for _, frag := range cases {
		if err := writeRecord(&buf, contentTypeHandshake, frag); err != nil {
			t.Fatalf("writeRecord(%d bytes): %v", len(frag), err)
		}
	}

	for i, want := range cases {
		header, got, err := readRecord(&buf)
		if err != nil {
			t.Fatalf("readRecord %d: %v", i, err)
		}
		if header[0] != contentTypeHandshake {
			t.Errorf("record %d: type = %d", i, header[0])
		}
		if !bytes.Equal(got, want) {
			t.Errorf("record %d: fragment mismatch (len got=%d want=%d)",
				i, len(got), len(want))
		}
	}
}

// --- Nonce derivation -------------------------------------------------------

func TestNonceForSeq_ZeroSeqEqualsIV(t *testing.T) {
	var iv [aeadIVLen]byte
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	got := nonceForSeq(iv, 0)
	if got != iv {
		t.Errorf("nonce(seq=0) = %x, want iv = %x", got, iv)
	}
}

func TestNonceForSeq_AllZeroIVPlacesSeqInTrailingBytes(t *testing.T) {
	var iv [aeadIVLen]byte // all zeros
	got := nonceForSeq(iv, 0x0102030405060708)
	want := [aeadIVLen]byte{0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if got != want {
		t.Errorf("nonce = %x, want %x", got, want)
	}
}

func TestNonceForSeq_XORsCorrectly(t *testing.T) {
	iv := [aeadIVLen]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	got := nonceForSeq(iv, 0x0102030405060708)
	// First 4 bytes of "padded seq" are 0; XOR with 0xFF leaves 0xFF.
	// Last 8 bytes are seq XOR 0xFF…
	want := [aeadIVLen]byte{
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF ^ 0x01, 0xFF ^ 0x02, 0xFF ^ 0x03, 0xFF ^ 0x04,
		0xFF ^ 0x05, 0xFF ^ 0x06, 0xFF ^ 0x07, 0xFF ^ 0x08,
	}
	if got != want {
		t.Errorf("nonce = %x, want %x", got, want)
	}
}

// TestNonceForSeq_DifferentSeqsProduceDifferentNonces is the property GCM
// security relies on. If this ever fails, GCM is no longer safe with this
// key.
func TestNonceForSeq_DifferentSeqsProduceDifferentNonces(t *testing.T) {
	iv := [aeadIVLen]byte{0xAA, 0xBB, 0xCC}
	a := nonceForSeq(iv, 0)
	b := nonceForSeq(iv, 1)
	c := nonceForSeq(iv, 1<<32)
	if a == b || b == c || a == c {
		t.Errorf("nonces collided: a=%x b=%x c=%x", a, b, c)
	}
}

// --- Seal / Open roundtrip --------------------------------------------------

// fixedKeys returns a pair of recordKeys (sealer, opener) sharing the same
// key/IV, both starting at seq=0. Used for paired encrypt+decrypt tests.
func fixedKeys(t *testing.T) (*recordKeys, *recordKeys) {
	t.Helper()
	key := bytes.Repeat([]byte{0xA5}, aeadKeyLen)
	iv := bytes.Repeat([]byte{0x5A}, aeadIVLen)
	sealer, err := newRecordKeys(key, iv)
	if err != nil {
		t.Fatalf("newRecordKeys: %v", err)
	}
	opener, err := newRecordKeys(key, iv)
	if err != nil {
		t.Fatalf("newRecordKeys: %v", err)
	}
	return sealer, opener
}

func TestNewRecordKeys_RejectsBadKeyLength(t *testing.T) {
	_, err := newRecordKeys(make([]byte, 15), make([]byte, aeadIVLen))
	if !errors.Is(err, errInvalidKeyLength) {
		t.Errorf("err = %v, want errInvalidKeyLength", err)
	}
}

func TestNewRecordKeys_RejectsBadIVLength(t *testing.T) {
	_, err := newRecordKeys(make([]byte, aeadKeyLen), make([]byte, 13))
	if !errors.Is(err, errInvalidIVLength) {
		t.Errorf("err = %v, want errInvalidIVLength", err)
	}
}

func TestSealOpen_Roundtrip(t *testing.T) {
	sealer, opener := fixedKeys(t)

	plaintext := []byte("hello, TLS 1.3")
	record, err := sealer.Seal(contentTypeHandshake, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Outer header is the first 5 bytes; ciphertext is the rest.
	var header [recordHeaderLen]byte
	copy(header[:], record[:recordHeaderLen])
	if header[0] != contentTypeApplicationData {
		t.Errorf("outer type = %d, want %d (application_data hides real type)",
			header[0], contentTypeApplicationData)
	}

	innerType, got, err := opener.Open(header, record[recordHeaderLen:])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if innerType != contentTypeHandshake {
		t.Errorf("inner type = %d, want %d", innerType, contentTypeHandshake)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext = %q, want %q", got, plaintext)
	}
}

func TestSealOpen_EmptyPlaintext(t *testing.T) {
	// Spec allows zero-length content (a record carrying just the type byte).
	sealer, opener := fixedKeys(t)

	record, err := sealer.Seal(contentTypeApplicationData, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var header [recordHeaderLen]byte
	copy(header[:], record[:recordHeaderLen])
	innerType, got, err := opener.Open(header, record[recordHeaderLen:])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if innerType != contentTypeApplicationData {
		t.Errorf("inner type = %d", innerType)
	}
	if len(got) != 0 {
		t.Errorf("plaintext = %x, want empty", got)
	}
}

// TestSealOpen_AdvancesSeq: after N seals, the sealer's seq is at N. Same
// for opener. If this drifts, the next nonce is wrong and Open fails.
func TestSealOpen_AdvancesSeq(t *testing.T) {
	sealer, opener := fixedKeys(t)
	for i := 0; i < 5; i++ {
		record, err := sealer.Seal(contentTypeHandshake, []byte{byte(i)})
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		var header [recordHeaderLen]byte
		copy(header[:], record[:recordHeaderLen])
		_, _, err = opener.Open(header, record[recordHeaderLen:])
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
	}
	if sealer.seq != 5 {
		t.Errorf("sealer.seq = %d, want 5", sealer.seq)
	}
	if opener.seq != 5 {
		t.Errorf("opener.seq = %d, want 5", opener.seq)
	}
}

// TestSealOpen_TamperedHeaderFailsAuth: the outer header bytes are AAD, so
// any change to them must cause Open to fail.
func TestSealOpen_TamperedHeaderFailsAuth(t *testing.T) {
	sealer, opener := fixedKeys(t)

	record, err := sealer.Seal(contentTypeHandshake, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var header [recordHeaderLen]byte
	copy(header[:], record[:recordHeaderLen])
	header[0] = contentTypeAlert // different from what was sealed under

	_, _, err = opener.Open(header, record[recordHeaderLen:])
	if err == nil {
		t.Errorf("Open accepted record with tampered header")
	}
}

// TestSealOpen_TamperedCiphertextFailsAuth: flipping a single byte in the
// ciphertext must cause Open to fail (GCM tag mismatch).
func TestSealOpen_TamperedCiphertextFailsAuth(t *testing.T) {
	sealer, opener := fixedKeys(t)

	record, err := sealer.Seal(contentTypeHandshake, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var header [recordHeaderLen]byte
	copy(header[:], record[:recordHeaderLen])
	tampered := append([]byte(nil), record[recordHeaderLen:]...)
	tampered[0] ^= 0x01

	_, _, err = opener.Open(header, tampered)
	if err == nil {
		t.Errorf("Open accepted ciphertext with bit flip")
	}
}

// TestSealOpen_OutOfSyncSeqFailsAuth: opener at the wrong seq computes the
// wrong nonce and Open fails. Confirms that nonce really does include seq.
func TestSealOpen_OutOfSyncSeqFailsAuth(t *testing.T) {
	sealer, opener := fixedKeys(t)
	opener.seq = 7 // jump ahead of the sealer

	record, err := sealer.Seal(contentTypeHandshake, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var header [recordHeaderLen]byte
	copy(header[:], record[:recordHeaderLen])
	_, _, err = opener.Open(header, record[recordHeaderLen:])
	if err == nil {
		t.Errorf("Open succeeded with out-of-sync seq")
	}
}

// TestOpen_StripsZeroPadding: hand-construct a record with explicit trailing
// zeros, seal it, and confirm Open recovers exactly the prefix and the
// non-zero type byte sandwiched between them.
func TestOpen_StripsZeroPadding(t *testing.T) {
	// We bypass Seal to inject explicit padding: build the inner plaintext
	// manually and feed it to the AEAD.
	sealer, opener := fixedKeys(t)

	content := []byte{0x11, 0x22, 0x00, 0x33} // note interior zero — must NOT be stripped
	innerType := contentTypeApplicationData
	padding := []byte{0x00, 0x00, 0x00}

	inner := append(append(append([]byte{}, content...), innerType), padding...)

	ciphertextLen := len(inner) + sealer.aead.Overhead()
	var header [recordHeaderLen]byte
	header[0] = contentTypeApplicationData
	header[1], header[2] = 0x03, 0x03
	header[3] = byte(ciphertextLen >> 8)
	header[4] = byte(ciphertextLen)

	nonce := nonceForSeq(sealer.iv, sealer.seq)
	sealed := sealer.aead.Seal(nil, nonce[:], inner, header[:])

	gotType, gotPlain, err := opener.Open(header, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if gotType != innerType {
		t.Errorf("inner type = %d, want %d", gotType, innerType)
	}
	if !bytes.Equal(gotPlain, content) {
		t.Errorf("plaintext = %x, want %x (interior zero must survive)", gotPlain, content)
	}
}

// TestOpen_AllZeroInnerErrors: a decrypted inner with no non-zero byte means
// no content type byte was ever included. Per RFC 8446 §5.4, that's an
// invalid record.
func TestOpen_AllZeroInnerErrors(t *testing.T) {
	sealer, opener := fixedKeys(t)

	inner := make([]byte, 8) // all zeros — no type byte
	ciphertextLen := len(inner) + sealer.aead.Overhead()
	var header [recordHeaderLen]byte
	header[0] = contentTypeApplicationData
	header[1], header[2] = 0x03, 0x03
	header[3] = byte(ciphertextLen >> 8)
	header[4] = byte(ciphertextLen)

	nonce := nonceForSeq(sealer.iv, sealer.seq)
	sealed := sealer.aead.Seal(nil, nonce[:], inner, header[:])

	_, _, err := opener.Open(header, sealed)
	if !errors.Is(err, errEmptyInnerPlaintext) {
		t.Errorf("err = %v, want errEmptyInnerPlaintext", err)
	}
}

// TestOpen_FailedAuthDoesNotAdvanceSeq: a failed Open must leave the seq
// counter where it was, so a subsequent retry with the correct ciphertext
// (same seq) still authenticates.
func TestOpen_FailedAuthDoesNotAdvanceSeq(t *testing.T) {
	sealer, opener := fixedKeys(t)

	record, err := sealer.Seal(contentTypeHandshake, []byte("ok"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var header [recordHeaderLen]byte
	copy(header[:], record[:recordHeaderLen])
	bogus := append([]byte(nil), record[recordHeaderLen:]...)
	bogus[0] ^= 1

	if _, _, err := opener.Open(header, bogus); err == nil {
		t.Fatal("Open should have failed")
	}
	if opener.seq != 0 {
		t.Errorf("seq advanced after failed Open: got %d, want 0", opener.seq)
	}

	// Now the real ciphertext should still open at seq=0.
	innerType, got, err := opener.Open(header, record[recordHeaderLen:])
	if err != nil {
		t.Fatalf("Open after failed attempt: %v", err)
	}
	if innerType != contentTypeHandshake || !bytes.Equal(got, []byte("ok")) {
		t.Errorf("recovered = (%d, %q)", innerType, got)
	}
}

// TestSeal_RecordWireFormat checks that the wire-format header on a sealed
// record has the expected outer type, version, and length-field semantics.
func TestSeal_RecordWireFormat(t *testing.T) {
	sealer, _ := fixedKeys(t)
	plaintext := []byte("abcd")

	record, err := sealer.Seal(contentTypeHandshake, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if record[0] != contentTypeApplicationData {
		t.Errorf("outer type = %d, want application_data (%d)", record[0], contentTypeApplicationData)
	}
	if record[1] != 0x03 || record[2] != 0x03 {
		t.Errorf("legacy_record_version = %02x %02x, want 03 03", record[1], record[2])
	}
	declaredLen := int(record[3])<<8 | int(record[4])
	wantLen := len(plaintext) + 1 + aeadOverhead // +1 inner type, +16 GCM tag
	if declaredLen != wantLen {
		t.Errorf("declared length = %d, want %d", declaredLen, wantLen)
	}
	if len(record)-recordHeaderLen != declaredLen {
		t.Errorf("record body len (%d) != declared length (%d)",
			len(record)-recordHeaderLen, declaredLen)
	}
}
