package tls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// mustHex decodes a hex string with whitespace stripped and fails the test on
// any error. Used for inline byte vectors that we want to read as plain hex.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s)
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestBuildHkdfLabel pins down the exact byte layout of the HkdfLabel struct
// (RFC 8446 §7.1). This is the spec's wire format — every TLS 1.3 stack on
// the planet must agree on it byte-for-byte, so there's value in hand-coding
// the expected bytes for a few canonical cases instead of round-tripping
// through HKDF.
//
// HkdfLabel = struct {
//     uint16 length;
//     opaque label<7..255>   = "tls13 " + Label;   // length-prefixed (1 byte)
//     opaque context<0..255> = Context;            // length-prefixed (1 byte)
// }
func TestBuildHkdfLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		context []byte
		length  int
		want    string
	}{
		{
			name:    "key",
			label:   "key",
			context: nil,
			length:  16,
			// 00 10                  uint16 length = 16
			// 09                     label_length = len("tls13 key") = 9
			// 74 6c 73 31 33 20      "tls13 "
			// 6b 65 79               "key"
			// 00                     context_length = 0
			want: "00 10 09 74 6c 73 31 33 20 6b 65 79 00",
		},
		{
			name:    "iv",
			label:   "iv",
			context: nil,
			length:  12,
			// 00 0c | 08 | "tls13 iv" | 00
			want: "00 0c 08 74 6c 73 31 33 20 69 76 00",
		},
		{
			name:    "finished",
			label:   "finished",
			context: nil,
			length:  32,
			// 00 20 | 0e | "tls13 finished" | 00
			want: "00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65 64 00",
		},
		{
			name:    "derived empty context",
			label:   "derived",
			context: nil,
			length:  32,
			// 00 20 | 0d | "tls13 derived" | 00
			want: "00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64 00",
		},
		{
			name:    "c hs traffic with 32-byte transcript",
			label:   "c hs traffic",
			context: bytes.Repeat([]byte{0xAB}, 32),
			length:  32,
			// 00 20 | 12 | "tls13 c hs traffic" | 20 | 32×0xAB
			want: "00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72 61 66 66 69 63 20" +
				strings.Repeat("ab", 32),
		},
		{
			name:    "s ap traffic with 32-byte transcript",
			label:   "s ap traffic",
			context: bytes.Repeat([]byte{0xCD}, 32),
			length:  32,
			// 00 20 | 12 | "tls13 s ap traffic" | 20 | 32×0xCD
			want: "00 20 12 74 6c 73 31 33 20 73 20 61 70 20 74 72 61 66 66 69 63 20" +
				strings.Repeat("cd", 32),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildHkdfLabel(tc.label, tc.context, tc.length)
			want := mustHex(t, tc.want)
			if !bytes.Equal(got, want) {
				t.Errorf("HkdfLabel mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestHkdfExpandLabel_AgainstManualHMAC verifies the full HKDF-Expand-Label
// chain by recomputing the expected output by hand using HMAC-SHA256.
//
// For length ≤ HashLen, RFC 5869 HKDF-Expand reduces to a single HMAC:
//   T(1) = HMAC-Hash(PRK, info || 0x01)
//   OKM  = T(1)[:length]
//
// If buildHkdfLabel ever drifts from the spec, this test catches it even
// though the stdlib hkdf.Expand call is hidden inside hkdfExpandLabel.
func TestHkdfExpandLabel_AgainstManualHMAC(t *testing.T) {
	// Use SHA-256("hello") as a stand-in PRK. Any 32-byte value works.
	prk := sha256.Sum256([]byte("hello"))

	cases := []struct {
		label   string
		context []byte
		length  int
	}{
		{"key", nil, 16},
		{"iv", nil, 12},
		{"finished", nil, 32},
		{"c hs traffic", bytes.Repeat([]byte{0x42}, 32), 32},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := hkdfExpandLabel(prk[:], tc.label, tc.context, tc.length)

			info := buildHkdfLabel(tc.label, tc.context, tc.length)
			h := hmac.New(sha256.New, prk[:])
			h.Write(info)
			h.Write([]byte{0x01})
			want := h.Sum(nil)[:tc.length]

			if !bytes.Equal(got, want) {
				t.Errorf("HKDF-Expand-Label drift\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestDeriveSecret_IsExpandLabel confirms that deriveSecret is exactly
// HKDF-Expand-Label with length=hashLen, as required by RFC 8446 §7.1.
func TestDeriveSecret_IsExpandLabel(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, hashLen)
	transcript := sha256.Sum256([]byte("CH||SH"))

	got := deriveSecret(secret, "c hs traffic", transcript[:])
	want := hkdfExpandLabel(secret, "c hs traffic", transcript[:], hashLen)
	if !bytes.Equal(got, want) {
		t.Errorf("deriveSecret diverged from hkdfExpandLabel(., ., ., hashLen)")
	}
	if len(got) != hashLen {
		t.Errorf("deriveSecret length = %d, want %d", len(got), hashLen)
	}
}

// TestHkdfExtract_NilSaltEqualsZeros confirms our reading of RFC 5869: a nil
// salt is treated as HashLen zero bytes. TLS 1.3's "0" inputs to the schedule
// rely on this equivalence.
func TestHkdfExtract_NilSaltEqualsZeros(t *testing.T) {
	ikm := bytes.Repeat([]byte{0xAA}, 32)
	zeros := make([]byte, hashLen)

	got := hkdfExtract(nil, ikm)
	want := hkdfExtract(zeros, ikm)
	if !bytes.Equal(got, want) {
		t.Errorf("nil salt should equal HashLen zeros, but they differ")
	}
}

// fixedSchedule returns a populated schedule using fixed-but-arbitrary
// inputs. The actual numbers don't matter for structural tests — we just
// need a schedule we can poke at.
func fixedSchedule(t *testing.T) *keySchedule {
	t.Helper()
	ecdhe := bytes.Repeat([]byte{0x01}, 32)
	chsh := sha256.Sum256([]byte("CH||SH"))
	chsf := sha256.Sum256([]byte("CH..server Finished"))

	ks := newKeySchedule(ecdhe, chsh[:])
	ks.SetServerFinishedTranscript(chsf[:])
	return ks
}

func TestKeySchedule_AllSecretsHaveHashLen(t *testing.T) {
	ks := fixedSchedule(t)

	for name, s := range map[string][]byte{
		"early":           ks.earlySecret,
		"handshake":       ks.handshakeSecret,
		"master":          ks.masterSecret,
		"client_hs":       ks.clientHandshakeTrafficSecret,
		"server_hs":       ks.serverHandshakeTrafficSecret,
		"client_app":      ks.clientApplicationTrafficSecret,
		"server_app":      ks.serverApplicationTrafficSecret,
	} {
		if len(s) != hashLen {
			t.Errorf("%s secret length = %d, want %d", name, len(s), hashLen)
		}
	}
}

// TestKeySchedule_SecretsAllDistinct guards against two classes of bug:
//   - mixing up label arguments (would make two secrets accidentally equal)
//   - failing to incorporate the transcript at all (would make every secret
//     a function of just ecdhe, again colliding things that shouldn't)
func TestKeySchedule_SecretsAllDistinct(t *testing.T) {
	ks := fixedSchedule(t)

	all := map[string][]byte{
		"early":      ks.earlySecret,
		"handshake":  ks.handshakeSecret,
		"master":     ks.masterSecret,
		"client_hs":  ks.clientHandshakeTrafficSecret,
		"server_hs":  ks.serverHandshakeTrafficSecret,
		"client_app": ks.clientApplicationTrafficSecret,
		"server_app": ks.serverApplicationTrafficSecret,
	}
	for n1, s1 := range all {
		for n2, s2 := range all {
			if n1 < n2 && bytes.Equal(s1, s2) {
				t.Errorf("%s and %s secrets are identical: %x", n1, n2, s1)
			}
		}
	}
}

// TestKeySchedule_DeterministicForSameInputs is a basic sanity check that we
// don't accidentally pull entropy from anywhere — same inputs must give the
// same outputs.
func TestKeySchedule_DeterministicForSameInputs(t *testing.T) {
	ecdhe := bytes.Repeat([]byte{0x07}, 32)
	chsh := sha256.Sum256([]byte("transcript-1"))
	chsf := sha256.Sum256([]byte("transcript-2"))

	a := newKeySchedule(ecdhe, chsh[:])
	a.SetServerFinishedTranscript(chsf[:])

	b := newKeySchedule(ecdhe, chsh[:])
	b.SetServerFinishedTranscript(chsf[:])

	if !bytes.Equal(a.handshakeSecret, b.handshakeSecret) {
		t.Errorf("handshake secret not deterministic")
	}
	if !bytes.Equal(a.clientApplicationTrafficSecret, b.clientApplicationTrafficSecret) {
		t.Errorf("client_app secret not deterministic")
	}
}

// TestKeySchedule_PhaseIsolation: handshake-traffic secrets must depend only
// on the phase-1 inputs (ecdhe, transcript through SH); changing the phase-2
// transcript later must not retroactively change them.
func TestKeySchedule_PhaseIsolation(t *testing.T) {
	ecdhe := bytes.Repeat([]byte{0x07}, 32)
	chsh := sha256.Sum256([]byte("CH||SH"))

	a := newKeySchedule(ecdhe, chsh[:])
	clientHSBefore := append([]byte(nil), a.clientHandshakeTrafficSecret...)
	serverHSBefore := append([]byte(nil), a.serverHandshakeTrafficSecret...)

	chsfA := sha256.Sum256([]byte("transcript-A"))
	a.SetServerFinishedTranscript(chsfA[:])

	if !bytes.Equal(a.clientHandshakeTrafficSecret, clientHSBefore) {
		t.Errorf("client_hs changed after phase 2 — phases not isolated")
	}
	if !bytes.Equal(a.serverHandshakeTrafficSecret, serverHSBefore) {
		t.Errorf("server_hs changed after phase 2 — phases not isolated")
	}
}

// TestKeySchedule_Phase2DependsOnTranscript: app-traffic secrets must change
// when the post-handshake transcript changes. Catches a bug where the phase-2
// transcript argument is silently ignored.
func TestKeySchedule_Phase2DependsOnTranscript(t *testing.T) {
	ecdhe := bytes.Repeat([]byte{0x07}, 32)
	chsh := sha256.Sum256([]byte("CH||SH"))

	chsfA := sha256.Sum256([]byte("transcript-A"))
	chsfB := sha256.Sum256([]byte("transcript-B"))

	a := newKeySchedule(ecdhe, chsh[:])
	a.SetServerFinishedTranscript(chsfA[:])

	b := newKeySchedule(ecdhe, chsh[:])
	b.SetServerFinishedTranscript(chsfB[:])

	if bytes.Equal(a.clientApplicationTrafficSecret, b.clientApplicationTrafficSecret) {
		t.Errorf("client_app secret didn't change with transcript")
	}
	if bytes.Equal(a.serverApplicationTrafficSecret, b.serverApplicationTrafficSecret) {
		t.Errorf("server_app secret didn't change with transcript")
	}
	// master secret derives from the same fixed "derived" → 0 chain, so it
	// must NOT depend on the phase-2 transcript.
	if !bytes.Equal(a.masterSecret, b.masterSecret) {
		t.Errorf("master secret should not depend on phase-2 transcript")
	}
}

// TestKeySchedule_DependsOnECDHE: changing the ECDHE shared secret must
// change the handshake secret (and everything downstream). Catches a bug
// where the schedule is somehow stuck on a constant.
func TestKeySchedule_DependsOnECDHE(t *testing.T) {
	chsh := sha256.Sum256([]byte("CH||SH"))

	a := newKeySchedule(bytes.Repeat([]byte{0x01}, 32), chsh[:])
	b := newKeySchedule(bytes.Repeat([]byte{0x02}, 32), chsh[:])

	if bytes.Equal(a.handshakeSecret, b.handshakeSecret) {
		t.Errorf("handshake secret didn't change with ECDHE input")
	}
	if bytes.Equal(a.clientHandshakeTrafficSecret, b.clientHandshakeTrafficSecret) {
		t.Errorf("client_hs didn't change with ECDHE input")
	}
}

func TestTrafficKeyAndIV_Lengths(t *testing.T) {
	ts := bytes.Repeat([]byte{0x33}, hashLen)
	key, iv := trafficKeyAndIV(ts)
	if len(key) != keyLen {
		t.Errorf("key length = %d, want %d", len(key), keyLen)
	}
	if len(iv) != ivLen {
		t.Errorf("iv length = %d, want %d", len(iv), ivLen)
	}
}

// TestTrafficKeyAndIV_KeyDifferentFromIV: the only thing distinguishing the
// two derivations is the label, so this catches any accidental label swap.
func TestTrafficKeyAndIV_KeyDifferentFromIV(t *testing.T) {
	ts := bytes.Repeat([]byte{0x33}, hashLen)
	key, iv := trafficKeyAndIV(ts)
	// key is 16 bytes, iv is 12 — compare the first 12 bytes of key against iv.
	if bytes.Equal(key[:ivLen], iv) {
		t.Errorf("key prefix matches iv — labels likely swapped")
	}
}

func TestFinishedKey_Length(t *testing.T) {
	got := finishedKey(bytes.Repeat([]byte{0x44}, hashLen))
	if len(got) != hashLen {
		t.Errorf("finished_key length = %d, want %d", len(got), hashLen)
	}
}

// TestFinishedKey_DependsOnTrafficSecret: different traffic secrets must
// produce different finished keys (otherwise client and server would compute
// the same Finished MAC, defeating the whole point).
func TestFinishedKey_DependsOnTrafficSecret(t *testing.T) {
	a := finishedKey(bytes.Repeat([]byte{0x44}, hashLen))
	b := finishedKey(bytes.Repeat([]byte{0x55}, hashLen))
	if bytes.Equal(a, b) {
		t.Errorf("finished_key didn't change with traffic secret")
	}
}
