package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

// mustHex32 decodes a 64-char hex string into a [32]byte. Used for inline
// RFC 7748 test vectors so the tests read like the spec text.
func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	if len(b) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// --- Field arithmetic ------------------------------------------------------

func TestField_AddCommutative(t *testing.T) {
	a := new(big.Int).SetInt64(123456789)
	b := new(big.Int).SetInt64(987654321)
	ab := feAdd(a, b)
	ba := feAdd(b, a)
	if ab.Cmp(ba) != 0 {
		t.Errorf("a+b (%s) != b+a (%s)", ab, ba)
	}
}

func TestField_AddWrapsModP(t *testing.T) {
	// (p-1) + 2 ≡ 1 (mod p)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	got := feAdd(pMinus1, big.NewInt(2))
	if got.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("(p-1) + 2 = %s, want 1", got)
	}
}

func TestField_SubWrapsModP(t *testing.T) {
	// 0 - 1 ≡ p-1 (mod p)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	got := feSub(big.NewInt(0), big.NewInt(1))
	if got.Cmp(pMinus1) != 0 {
		t.Errorf("0 - 1 = %s, want p-1 (%s)", got, pMinus1)
	}
}

func TestField_MulWrapsModP(t *testing.T) {
	// (p-1) * (p-1) ≡ 1 (mod p)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	got := feMul(pMinus1, pMinus1)
	if got.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("(p-1)² = %s, want 1", got)
	}
}

func TestField_InverseRoundtrip(t *testing.T) {
	cases := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(42),
		new(big.Int).Sub(p, big.NewInt(1)), // p-1
		new(big.Int).Sub(p, big.NewInt(2)), // p-2
	}
	for _, a := range cases {
		inv := feInverse(a)
		one := feMul(a, inv)
		if one.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("(%s)·(%s)⁻¹ = %s, want 1", a, a, one)
		}
	}
}

// --- Encoding / clamp -------------------------------------------------------

func TestClampScalar_BitPattern(t *testing.T) {
	// All ones in: clamping must clear the documented bits.
	var ones [32]byte
	for i := range ones {
		ones[i] = 0xFF
	}
	out := clampScalar(ones)
	if out[0] != 0xF8 {
		t.Errorf("clamp(0xFF…)[0] = %02x, want F8", out[0])
	}
	if out[31] != 0x7F {
		t.Errorf("clamp(0xFF…)[31] = %02x, want 7F", out[31])
	}
	// All zeros in: bit 6 of byte 31 must be set.
	var zeros [32]byte
	out = clampScalar(zeros)
	if out[0] != 0x00 {
		t.Errorf("clamp(0x00…)[0] = %02x, want 00", out[0])
	}
	if out[31] != 0x40 {
		t.Errorf("clamp(0x00…)[31] = %02x, want 40", out[31])
	}
	// Middle bytes should pass through untouched.
	mid := zeros
	for i := 1; i < 31; i++ {
		mid[i] = byte(i + 1)
	}
	out = clampScalar(mid)
	for i := 1; i < 31; i++ {
		if out[i] != byte(i+1) {
			t.Errorf("clamp altered middle byte %d: got %02x, want %02x", i, out[i], i+1)
		}
	}
}

func TestDecodeUCoordinate_MasksHighBit(t *testing.T) {
	// Byte 31 = 0x80 (only the to-be-masked bit set) → decoded value is 0.
	var withBit [32]byte
	withBit[31] = 0x80
	got := decodeUCoordinate(withBit)
	if got.Sign() != 0 {
		t.Errorf("decode([0…0,0x80]) = %s, want 0 (high bit must be masked)", got)
	}

	// Byte 31 = 0xC0 → high bit masked off, only bit 6 remains.
	withBit[31] = 0xC0
	got = decodeUCoordinate(withBit)
	want := new(big.Int).Lsh(big.NewInt(1), 254) // 2²⁵⁴
	if got.Cmp(want) != 0 {
		t.Errorf("decode([0…0,0xC0]) = %s, want 2²⁵⁴", got)
	}
}

func TestEncodeUCoordinate_FixedWidth(t *testing.T) {
	// Small values must still be 32 bytes, little-endian, zero-padded.
	one := big.NewInt(1)
	out := encodeUCoordinate(one)
	if out[0] != 0x01 {
		t.Errorf("encode(1)[0] = %02x, want 01", out[0])
	}
	for i := 1; i < 32; i++ {
		if out[i] != 0 {
			t.Errorf("encode(1)[%d] = %02x, want 00 (should be zero-padded)", i, out[i])
		}
	}
}

func TestEncodeDecode_Roundtrip(t *testing.T) {
	// Canonical input (high bit of byte 31 already clear) must roundtrip
	// exactly.
	in := mustHex32(t, "1122334455667788991011121314151617181920212223242526272829303142")
	got := encodeUCoordinate(decodeUCoordinate(in))
	if got != in {
		t.Errorf("roundtrip:\n in:  %x\n out: %x", in, got)
	}
}

// --- RFC 7748 §5.2 test vectors --------------------------------------------

func TestX25519_RFC7748_Vector1(t *testing.T) {
	scalar := mustHex32(t, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	u := mustHex32(t, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	want := mustHex32(t, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

	if got := scalarMult(scalar, u); got != want {
		t.Errorf("scalar·u\n got:  %x\n want: %x", got, want)
	}
}

// Note: vector 2's u-coordinate has the high bit of byte 31 set (0x93). RFC
// 7748 §5 explicitly requires that bit to be masked off, so this test also
// pins down our decodeUCoordinate masking behavior end-to-end.
func TestX25519_RFC7748_Vector2(t *testing.T) {
	scalar := mustHex32(t, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
	u := mustHex32(t, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
	want := mustHex32(t, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

	if got := scalarMult(scalar, u); got != want {
		t.Errorf("scalar·u\n got:  %x\n want: %x", got, want)
	}
}

// RFC 7748 §5.2 specifies an iterative test where you repeatedly compute
// k_(i+1) = X25519(k_i, u_i) and u_(i+1) = k_i, starting from k_0 = u_0 = 9.
// The vector after 1 iteration is a fast, strong end-to-end check.
// (Full 1k / 1M vectors are omitted because math/big is too slow for them.)
func TestX25519_RFC7748_OneIteration(t *testing.T) {
	var k [32]byte
	k[0] = 9
	u := k

	want := mustHex32(t, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
	if got := scalarMult(k, u); got != want {
		t.Errorf("X25519(9, 9)\n got:  %x\n want: %x", got, want)
	}
}

// --- RFC 7748 §6.1 Diffie-Hellman test --------------------------------------

func TestX25519_RFC7748_DH_AliceBob(t *testing.T) {
	alicePriv := mustHex32(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex32(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex32(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shared := mustHex32(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	if got := x25519Base(alicePriv); got != alicePub {
		t.Errorf("alice pub:\n got:  %x\n want: %x", got, alicePub)
	}
	if got := x25519Base(bobPriv); got != bobPub {
		t.Errorf("bob pub:\n got:  %x\n want: %x", got, bobPub)
	}

	s1, err := x25519(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("alice·bob_pub: %v", err)
	}
	if s1 != shared {
		t.Errorf("alice·bob_pub:\n got:  %x\n want: %x", s1, shared)
	}

	s2, err := x25519(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("bob·alice_pub: %v", err)
	}
	if s2 != shared {
		t.Errorf("bob·alice_pub:\n got:  %x\n want: %x", s2, shared)
	}
	if s1 != s2 {
		t.Errorf("DH not symmetric: alice got %x, bob got %x", s1, s2)
	}
}

// --- Cross-check vs crypto/ecdh ---------------------------------------------

// TestX25519_PublicKeyAgainstStdlib generates random scalars and checks that
// our basepoint multiplication produces the same public key as crypto/ecdh
// for each one. 32 random tries gives strong probabilistic coverage of the
// scalar space.
func TestX25519_PublicKeyAgainstStdlib(t *testing.T) {
	curve := ecdh.X25519()
	for i := 0; i < 32; i++ {
		var priv [32]byte
		if _, err := rand.Read(priv[:]); err != nil {
			t.Fatal(err)
		}

		stdPriv, err := curve.NewPrivateKey(priv[:])
		if err != nil {
			t.Fatalf("stdlib NewPrivateKey: %v", err)
		}
		stdPub := stdPriv.PublicKey().Bytes()

		ourPub := x25519Base(priv)

		if !bytes.Equal(stdPub, ourPub[:]) {
			t.Errorf("public-key mismatch (iter %d, priv=%x):\n  ours: %x\n  std:  %x",
				i, priv, ourPub, stdPub)
		}
	}
}

// TestX25519_SharedSecretAgainstStdlib runs full DH against crypto/ecdh: we
// generate two random keys, compute the shared secret both ways with both
// implementations, and assert they all agree.
func TestX25519_SharedSecretAgainstStdlib(t *testing.T) {
	curve := ecdh.X25519()
	for i := 0; i < 16; i++ {
		var aPriv, bPriv [32]byte
		if _, err := rand.Read(aPriv[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(bPriv[:]); err != nil {
			t.Fatal(err)
		}

		stdAPriv, err := curve.NewPrivateKey(aPriv[:])
		if err != nil {
			t.Fatal(err)
		}
		stdBPriv, err := curve.NewPrivateKey(bPriv[:])
		if err != nil {
			t.Fatal(err)
		}
		stdShared, err := stdAPriv.ECDH(stdBPriv.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		bPub := x25519Base(bPriv)
		ourShared, err := x25519(aPriv, bPub)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(stdShared, ourShared[:]) {
			t.Errorf("shared-secret mismatch (iter %d):\n  ours: %x\n  std:  %x",
				i, ourShared, stdShared)
		}
	}
}

// --- Defensive checks -------------------------------------------------------

func TestX25519_RejectsAllZeroSharedSecret(t *testing.T) {
	// All-zero peer public is one of the canonical low-order points: scalar
	// multiplication produces an all-zero output regardless of our scalar.
	// RFC 7748 §6.1 mandates rejecting that.
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	var zeroPeer [32]byte

	got, err := x25519(priv, zeroPeer)
	if err == nil {
		t.Errorf("x25519 with zero peer must error, got %x", got)
	}
}

func TestX25519_BasepointShape(t *testing.T) {
	// RFC 7748 §4.1: u = 9 is the canonical generator.
	if x25519Basepoint[0] != 9 {
		t.Errorf("basepoint[0] = %d, want 9", x25519Basepoint[0])
	}
	for i := 1; i < 32; i++ {
		if x25519Basepoint[i] != 0 {
			t.Errorf("basepoint[%d] = %02x, want 00", i, x25519Basepoint[i])
		}
	}
}
