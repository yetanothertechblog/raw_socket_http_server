package tls

import (
	"crypto/sha256"
	"hash"
)

// transcript is the running SHA-256 of every handshake message exchanged
// so far, in wire-byte order, *including* each message's 4-byte handshake
// header. Per RFC 8446 §4.4.1:
//
//	Transcript-Hash(M1, M2, ..., Mn) = Hash(M1 || M2 || ... || Mn)
//
// Several derivations snapshot this hash at specific points (CHSH, after CV,
// CHSF) — each call to sum() returns a copy of the current digest without
// disturbing the running hash, so further messages can keep being appended.
type transcript struct {
	h hash.Hash
}

func newTranscript() *transcript {
	return &transcript{h: sha256.New()}
}

// update appends one full handshake message (header + body) to the transcript.
func (t *transcript) update(msg []byte) {
	t.h.Write(msg)
}

// sum returns the SHA-256 of all bytes appended so far. The hash state is
// not reset, so subsequent updates continue to extend the same transcript.
func (t *transcript) sum() []byte {
	return t.h.Sum(nil)
}
