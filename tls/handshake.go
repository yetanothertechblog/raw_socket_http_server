package tls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
)

// Handshake runs the server-side TLS 1.3 1-RTT handshake to completion. It
// is idempotent — a second call after success returns nil immediately, and
// after a failure returns the original error. The handshake is also
// triggered automatically on the first Read or Write.
//
// On success, c.readKeys / c.writeKeys hold the application-traffic AEAD
// keys and c.handshakeDone is true.
//
// The flow we implement (RFC 8446 §2):
//
//	C -> S  ClientHello                                 (plaintext)
//	S -> C  ServerHello                                 (plaintext)
//	            * derive handshake-traffic keys *
//	S -> C  {EncryptedExtensions}                       (encrypted)
//	S -> C  {Certificate}                               (encrypted)
//	S -> C  {CertificateVerify}                         (encrypted)
//	S -> C  {Finished}                                  (encrypted)
//	            * derive application-traffic keys *
//	C -> S  {Finished}                                  (encrypted under client HS keys)
//	            * application data flows under app keys *
//
// Curly braces denote AEAD-protected records. Brackets [...] in RFC 8446
// (0-RTT data) are absent from our implementation.
func (c *Conn) Handshake() error {
	if c.handshakeDone {
		return nil
	}
	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if err := c.runHandshake(); err != nil {
		c.handshakeErr = err
		return err
	}
	c.handshakeDone = true
	return nil
}

func (c *Conn) runHandshake() error {
	if c.identity == nil {
		return errors.New("tls: server identity not set")
	}

	tx := newTranscript()

	// 1. ClientHello (plaintext).
	chMsg, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read ClientHello: %w", err)
	}
	if chMsg[0] != handshakeTypeClientHello {
		return fmt.Errorf("expected ClientHello, got handshake type %d", chMsg[0])
	}
	tx.update(chMsg)
	hello, err := parseClientHello(chMsg[handshakeHeaderLen:])
	if err != nil {
		return fmt.Errorf("parse ClientHello: %w", err)
	}
	if err := validateClientHello(hello); err != nil {
		return err
	}

	// 2. Server x25519 ephemeral, ECDHE shared secret.
	var serverPriv [32]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		return fmt.Errorf("rand for server x25519: %w", err)
	}
	serverPub := x25519Base(serverPriv)

	clientShare := hello.findKeyShare(namedGroupX25519)
	var clientPub [32]byte
	copy(clientPub[:], clientShare)
	shared, err := x25519(serverPriv, clientPub)
	if err != nil {
		return fmt.Errorf("x25519 ECDHE: %w", err)
	}

	// 3. ServerHello (plaintext).
	var serverRandom [32]byte
	if _, err := rand.Read(serverRandom[:]); err != nil {
		return fmt.Errorf("rand for ServerHello: %w", err)
	}
	shBody := marshalServerHello(serverRandom, hello.legacySessionID, serverPub)
	shMsg := marshalHandshake(handshakeTypeServerHello, shBody)
	if err := c.writePlaintextHandshake(shMsg); err != nil {
		return fmt.Errorf("write ServerHello: %w", err)
	}
	tx.update(shMsg)

	// 4. Derive handshake-traffic keys from ECDHE shared + transcript(CH..SH).
	transcriptCHSH := tx.sum()
	schedule := newKeySchedule(shared[:], transcriptCHSH)

	clientHSKeys, err := newRecordKeysFromSecret(schedule.clientHandshakeTrafficSecret)
	if err != nil {
		return err
	}
	serverHSKeys, err := newRecordKeysFromSecret(schedule.serverHandshakeTrafficSecret)
	if err != nil {
		return err
	}
	c.readKeys = clientHSKeys
	c.writeKeys = serverHSKeys

	// 5. Send a fake ChangeCipherSpec for middlebox compatibility (RFC 8446
	// §D.4). Some middleboxes look for it and drop the connection if absent.
	// Curl and the Go stdlib client do not require it, but it's cheap and
	// real-world clients in the wild often do.
	if err := writeRecord(c.raw, contentTypeChangeCipherSpec, []byte{0x01}); err != nil {
		return fmt.Errorf("write CCS: %w", err)
	}

	// 6. EncryptedExtensions (no extensions to send).
	eeMsg := marshalHandshake(handshakeTypeEncryptedExtensions, marshalEncryptedExtensions())
	if err := c.writeEncryptedHandshake(eeMsg); err != nil {
		return fmt.Errorf("write EncryptedExtensions: %w", err)
	}
	tx.update(eeMsg)

	// 7. Certificate.
	certMsg := marshalHandshake(handshakeTypeCertificate, marshalCertificate(c.identity.certDER))
	if err := c.writeEncryptedHandshake(certMsg); err != nil {
		return fmt.Errorf("write Certificate: %w", err)
	}
	tx.update(certMsg)

	// 8. CertificateVerify — sign the transcript through Certificate.
	transcriptForCV := tx.sum()
	sig := c.identity.signCertificateVerify(transcriptForCV)
	cvMsg := marshalHandshake(handshakeTypeCertificateVerify, marshalCertificateVerify(sigSchemeEd25519, sig))
	if err := c.writeEncryptedHandshake(cvMsg); err != nil {
		return fmt.Errorf("write CertificateVerify: %w", err)
	}
	tx.update(cvMsg)

	// 9. Server Finished — HMAC over transcript through CV using
	// server-handshake-traffic-secret's finished_key.
	transcriptBeforeServerFin := tx.sum()
	serverVerify := verifyData(schedule.serverHandshakeTrafficSecret, transcriptBeforeServerFin)
	finMsg := marshalHandshake(handshakeTypeFinished, marshalFinished(serverVerify))
	if err := c.writeEncryptedHandshake(finMsg); err != nil {
		return fmt.Errorf("write server Finished: %w", err)
	}
	tx.update(finMsg)

	// 10. Derive application-traffic keys from transcript(CH..ServerFinished).
	transcriptCHSF := tx.sum()
	schedule.SetServerFinishedTranscript(transcriptCHSF)

	// 11. Read client Finished. It's still under client handshake-traffic
	// keys (c.readKeys), and its verify_data is HMAC over the same CHSF
	// transcript using the client's finished_key.
	clientFinMsg, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read client Finished: %w", err)
	}
	if clientFinMsg[0] != handshakeTypeFinished {
		return fmt.Errorf("expected client Finished, got handshake type %d", clientFinMsg[0])
	}
	clientVerifyGot := clientFinMsg[handshakeHeaderLen:]
	clientVerifyWant := verifyData(schedule.clientHandshakeTrafficSecret, transcriptCHSF)
	if !bytes.Equal(clientVerifyGot, clientVerifyWant) {
		return errors.New("tls: client Finished verify_data mismatch")
	}

	// 12. Switch to application-traffic keys for both directions.
	clientAppKeys, err := newRecordKeysFromSecret(schedule.clientApplicationTrafficSecret)
	if err != nil {
		return err
	}
	serverAppKeys, err := newRecordKeysFromSecret(schedule.serverApplicationTrafficSecret)
	if err != nil {
		return err
	}
	c.readKeys = clientAppKeys
	c.writeKeys = serverAppKeys

	// hsBuf must be drained — anything left over is a protocol violation
	// (handshake messages may not be packed alongside app data records).
	if len(c.hsBuf) != 0 {
		return fmt.Errorf("tls: %d unexpected bytes after client Finished", len(c.hsBuf))
	}
	return nil
}

// validateClientHello enforces the policy our single-suite, single-curve,
// single-sig-scheme server requires. Anything missing is a hard error;
// we do not negotiate fallbacks.
func validateClientHello(h *clientHello) error {
	if !containsU16(h.supportedVersions, tls13Version) {
		return errors.New("tls: client did not offer TLS 1.3")
	}
	if !containsU16(h.cipherSuites, cipherTLSAES128GCMSHA256) {
		return errors.New("tls: client did not offer TLS_AES_128_GCM_SHA256")
	}
	if !containsU16(h.supportedGroups, namedGroupX25519) {
		return errors.New("tls: client did not offer x25519")
	}
	if !containsU16(h.signatureAlgorithms, sigSchemeEd25519) {
		return errors.New("tls: client did not offer ed25519")
	}
	share := h.findKeyShare(namedGroupX25519)
	if share == nil {
		// Strictly we should send HelloRetryRequest here. We don't
		// implement HRR — we just bail. In practice every curl/Go-stdlib
		// client sends an x25519 key_share when it offers x25519.
		return errors.New("tls: client offered x25519 but sent no x25519 key_share")
	}
	if len(share) != 32 {
		return fmt.Errorf("tls: x25519 key_share must be 32 bytes, got %d", len(share))
	}
	return nil
}

func containsU16(haystack []uint16, needle uint16) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// newRecordKeysFromSecret derives (key, IV) from a TLS 1.3 traffic secret
// per §7.3 and wraps them in a recordKeys with seq=0.
func newRecordKeysFromSecret(trafficSecret []byte) (*recordKeys, error) {
	key, iv := trafficKeyAndIV(trafficSecret)
	return newRecordKeys(key, iv)
}
