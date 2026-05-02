package tls

import (
	"errors"
	"math/big"
)

// X25519 ECDH (RFC 7748), implemented with math/big and the Montgomery ladder.
//
// Curve25519 is the Montgomery curve  y² = x³ + 486662·x² + x  over the prime
// field F_p with  p = 2²⁵⁵ - 19.  X25519 is "scalar multiplication using only
// the x-coordinate": given a 32-byte little-endian scalar k and a 32-byte
// little-endian u-coordinate, return the u-coordinate of the point k·P, where
// P is any curve point with the given input u-coordinate. Working only with
// x-coords lets us use the Montgomery ladder, which is a tight loop of just
// two formulas (xDBL+xADD combined into one "ladder step") per scalar bit.
//
// We deliberately use math/big for the field arithmetic. That's much slower
// than 26-bit-limb implementations, and — more importantly — math/big is NOT
// constant-time: Mul, Mod, ModInverse, and the conditional swap below all
// branch on operand value, which leaks scalar bits over a side channel.
// We accept that here because this code is for learning, not production
// crypto. Real handshakes should use crypto/ecdh.
//
// The conditional swap in the ladder is also implemented as a plain `if`,
// for the same reason. Spelling it out here so future-you, when porting this
// to fixed-width limbs, remembers that constant-time is the missing piece.

// p = 2²⁵⁵ - 19, the Curve25519 field prime.
var p = func() *big.Int {
	z := new(big.Int).Lsh(big.NewInt(1), 255)
	return z.Sub(z, big.NewInt(19))
}()

// pMinus2 is used as the exponent in Fermat's-little-theorem inversion:
// for a ≠ 0, a⁻¹ ≡ aᵖ⁻² (mod p).
var pMinus2 = new(big.Int).Sub(p, big.NewInt(2))

// a24 = (486662 - 2) / 4 = 121665.  This is the Curve25519-specific constant
// that appears in the ladder step's z₂ = E·(AA + a24·E) line.
var a24 = big.NewInt(121665)

// errZeroSharedSecret is returned by x25519 when scalar multiplication
// produces the all-zero output. RFC 7748 §6.1 mandates this check: it means
// the peer offered a low-order point, which would cause the shared secret to
// be predictable regardless of our private key. Equivalent to "abort and
// don't use the key".
var errZeroSharedSecret = errors.New("tls: X25519 produced all-zero shared secret (low-order point)")

// --- Field arithmetic over F_p ----------------------------------------------
//
// All field operations return a freshly-allocated *big.Int reduced mod p.
// We accept the allocation cost because it makes the ladder much easier to
// read; an in-place version would be ~20% faster but tangle the formulas.

func feAdd(a, b *big.Int) *big.Int {
	z := new(big.Int).Add(a, b)
	return z.Mod(z, p)
}

func feSub(a, b *big.Int) *big.Int {
	z := new(big.Int).Sub(a, b)
	return z.Mod(z, p)
}

func feMul(a, b *big.Int) *big.Int {
	z := new(big.Int).Mul(a, b)
	return z.Mod(z, p)
}

func feSquare(a *big.Int) *big.Int {
	return feMul(a, a)
}

// feInverse returns a⁻¹ mod p via Fermat's little theorem. Slow (~256 modular
// multiplications inside Exp) compared to the ~265-mul addition chain that
// optimized x25519 implementations use, but trivially correct.
func feInverse(a *big.Int) *big.Int {
	z := new(big.Int).Exp(a, pMinus2, p)
	return z
}

// --- Encoding / decoding ----------------------------------------------------

// decodeUCoordinate parses a 32-byte little-endian u-coordinate into a field
// element. Per RFC 7748 §5, implementations MUST mask the high bit of the
// final byte before decoding — the bit is reserved for sign-of-y in other
// formats and ignored here.
func decodeUCoordinate(in [32]byte) *big.Int {
	masked := in
	masked[31] &= 0x7F

	// math/big.SetBytes wants big-endian, so reverse first.
	var be [32]byte
	for i := 0; i < 32; i++ {
		be[i] = masked[31-i]
	}
	return new(big.Int).SetBytes(be[:])
}

// encodeUCoordinate serializes a field element as 32 little-endian bytes,
// zero-padded on the high end. The output is always exactly 32 bytes — even
// for small values — because the wire format is fixed-width.
func encodeUCoordinate(a *big.Int) [32]byte {
	// Reduce just in case, so we never emit a value ≥ p.
	reduced := new(big.Int).Mod(a, p)

	var be [32]byte
	reduced.FillBytes(be[:]) // big-endian, zero-padded to 32 bytes

	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = be[31-i]
	}
	return out
}

// clampScalar applies the RFC 7748 §5 scalar clamping:
//
//	scalar[0]  &= 248      // clear bits 0,1,2  → scalar is a multiple of 8
//	                       //   (so contributions from the curve's small
//	                       //   torsion subgroup vanish)
//	scalar[31] &= 127      // clear bit 7       → scalar < 2²⁵⁵
//	scalar[31] |= 64       // set bit 6         → scalar ≥ 2²⁵⁴, fixing the
//	                       //   length so the ladder runs the same number of
//	                       //   iterations regardless of the input
//
// These three constraints together neutralize the most common timing- and
// math-related footguns even for naïve ladder implementations.
func clampScalar(in [32]byte) [32]byte {
	out := in
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}

// --- Montgomery ladder ------------------------------------------------------

// scalarMult computes k·u on Curve25519, returning the u-coordinate of the
// result. This is the core of x25519: the scalar k is processed bit-by-bit,
// MSB to LSB, and at each step we update two projective points (R₀, R₁) such
// that the difference R₁ - R₀ is always equal to the input point P. That
// invariant lets us use the differential-addition formulas, which only
// involve x-coordinates.
//
// The variables follow the names used in RFC 7748 §5's pseudocode so the
// transcription is verifiable line-by-line.
func scalarMult(scalar, u [32]byte) [32]byte {
	k := clampScalar(scalar)
	x1 := decodeUCoordinate(u)

	// Projective state: R₀ represented as (x₂, z₂), R₁ as (x₃, z₃).
	// Initial state corresponds to R₀ = identity, R₁ = P, so R₁ - R₀ = P. ✓
	x2 := big.NewInt(1)
	z2 := big.NewInt(0)
	x3 := new(big.Int).Set(x1)
	z3 := big.NewInt(1)

	// "swap" tracks whether R₀ and R₁ are currently swapped. Using cumulative
	// XOR with each scalar bit lets us swap only when the bit changes — half
	// as many swaps on average. This is the standard RFC 7748 idiom.
	swap := uint(0)

	for t := 254; t >= 0; t-- {
		bit := uint((k[t/8] >> uint(t%8)) & 1)
		swap ^= bit
		if swap == 1 {
			x2, x3 = x3, x2
			z2, z3 = z3, z2
		}
		swap = bit

		// Ladder step (RFC 7748 §5). Computes  R₀ ← 2·R₀,  R₁ ← R₀ + R₁,
		// in projective x-only coordinates, using the x-coordinate of the
		// difference point (x₁) for the differential addition.
		A := feAdd(x2, z2)
		AA := feSquare(A)
		B := feSub(x2, z2)
		BB := feSquare(B)
		E := feSub(AA, BB)
		C := feAdd(x3, z3)
		D := feSub(x3, z3)
		DA := feMul(D, A)
		CB := feMul(C, B)
		x3 = feSquare(feAdd(DA, CB))
		z3 = feMul(x1, feSquare(feSub(DA, CB)))
		x2 = feMul(AA, BB)
		z2 = feMul(E, feAdd(AA, feMul(a24, E)))
	}

	// Final swap to undo any pending state change.
	if swap == 1 {
		x2, x3 = x3, x2
		z2, z3 = z3, z2
	}

	// Project back to affine: u = x₂ / z₂ = x₂ · z₂⁻¹.
	result := feMul(x2, feInverse(z2))
	return encodeUCoordinate(result)
}

// --- Public API -------------------------------------------------------------

// x25519Basepoint is u = 9, the canonical generator of the Curve25519 prime-
// order subgroup (RFC 7748 §4.1).
var x25519Basepoint = [32]byte{9}

// x25519Base computes scalar · G, the public-key half of an X25519 keypair.
// Equivalent to scalarMult(scalar, basepoint).
func x25519Base(scalar [32]byte) [32]byte {
	return scalarMult(scalar, x25519Basepoint)
}

// x25519 computes the X25519 shared secret: scalar · peer_public, i.e. the
// u-coordinate of the point obtained by scalar-multiplying the peer's public
// key by our private scalar.
//
// Per RFC 7748 §6.1, callers MUST reject the all-zero output to defend
// against contributory-behavior attacks where the peer sends a low-order
// public key. We do that check here so misuse is impossible.
func x25519(scalar, peerPublic [32]byte) ([32]byte, error) {
	out := scalarMult(scalar, peerPublic)
	var zero [32]byte
	if out == zero {
		return zero, errZeroSharedSecret
	}
	return out, nil
}
