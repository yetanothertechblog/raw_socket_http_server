package tls

import (
	"errors"
	"fmt"
	"io"
)

// Conn is a single server-side TLS 1.3 connection over an underlying
// io.ReadWriter (typically a *tcp.TCPConnection or a net.Conn). It runs the
// handshake on first Read or Write and thereafter exposes plaintext
// application data to its caller.
//
// Conn is *not* safe for concurrent use. Callers should treat it the same
// way they'd treat the underlying transport: one goroutine reading, one
// writing, or external synchronization.
type Conn struct {
	raw      io.ReadWriter
	identity *ServerIdentity

	// readKeys / writeKeys are nil before the handshake transitions to AEAD.
	// They are replaced wholesale at each rekey (handshake-traffic →
	// application-traffic) — never mutated in place.
	readKeys  *recordKeys
	writeKeys *recordKeys

	handshakeDone bool
	handshakeErr  error

	// inAppData is plaintext application data left over from a previously
	// decrypted record that wasn't fully drained by the last Read call.
	inAppData []byte

	// hsBuf collects handshake-message bytes that span multiple records or
	// records that contain multiple handshake messages. Used only during
	// the handshake; emptied when we cut over to application data.
	hsBuf []byte
}

// Server wraps raw with a TLS server-side state machine. The returned Conn
// will run the handshake lazily on the first Read or Write — call Handshake
// explicitly if you want the failure mode upfront instead of buried in a
// later read.
func Server(raw io.ReadWriter, identity *ServerIdentity) *Conn {
	return &Conn{raw: raw, identity: identity}
}

// Read returns plaintext application data. Triggers Handshake() if needed.
func (c *Conn) Read(p []byte) (int, error) {
	if !c.handshakeDone {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	for len(c.inAppData) == 0 {
		typ, plaintext, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		switch typ {
		case contentTypeApplicationData:
			c.inAppData = plaintext
		case contentTypeAlert:
			// Any alert from the peer ends the connection. We don't
			// distinguish warning vs. fatal — TLS 1.3 §6 explicitly says
			// implementations may treat all alerts as fatal.
			return 0, fmt.Errorf("tls: peer alert: % x", plaintext)
		case contentTypeHandshake:
			// Post-handshake messages (NewSessionTicket, KeyUpdate). We
			// don't implement them, but ignoring is the safe behavior
			// against a server that wouldn't issue them anyway.
			continue
		default:
			return 0, fmt.Errorf("tls: unexpected post-handshake record type %d", typ)
		}
	}
	n := copy(p, c.inAppData)
	c.inAppData = c.inAppData[n:]
	return n, nil
}

// Write encrypts p as one or more application_data records and pushes them
// out. Triggers Handshake() if needed. Records are sized at the plaintext
// limit (16 KiB) for predictable framing — chunking is not exposed.
func (c *Conn) Write(p []byte) (int, error) {
	if !c.handshakeDone {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	written := 0
	for written < len(p) {
		chunk := p[written:]
		if len(chunk) > maxPlaintextLength {
			chunk = chunk[:maxPlaintextLength]
		}
		sealed, err := c.writeKeys.Seal(contentTypeApplicationData, chunk)
		if err != nil {
			return written, err
		}
		if _, err := c.raw.Write(sealed); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

// Close closes the underlying transport, if it implements io.Closer. We do
// not send a close_notify alert — the HTTP server above us already signals
// end-of-response by closing the connection, and our test peers don't insist
// on the alert. (RFC 8446 §6.1 explicitly permits this.)
func (c *Conn) Close() error {
	if closer, ok := c.raw.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// readRecord pulls a single TLS record from the wire and returns
// (innerType, plaintext). Before AEAD is in effect, innerType is the outer
// record type and plaintext is the raw fragment. After AEAD is in effect,
// the record is decrypted and innerType is the type recovered from the
// inner plaintext.
func (c *Conn) readRecord() (uint8, []byte, error) {
	header, fragment, err := readRecord(c.raw)
	if err != nil {
		return 0, nil, err
	}

	if c.readKeys == nil {
		return header[0], fragment, nil
	}

	// Encrypted record: outer type must be application_data per §5.2. A
	// peer that sends contentTypeChangeCipherSpec at this point is doing
	// the legacy middlebox-compat trick — we accept it without decrypting.
	if header[0] == contentTypeChangeCipherSpec {
		return contentTypeChangeCipherSpec, fragment, nil
	}
	if header[0] != contentTypeApplicationData {
		return 0, nil, fmt.Errorf("tls: encrypted record outer type = %d, want %d", header[0], contentTypeApplicationData)
	}
	innerType, plaintext, err := c.readKeys.Open(header, fragment)
	if err != nil {
		return 0, nil, fmt.Errorf("tls: AEAD open failed: %w", err)
	}
	return innerType, plaintext, nil
}

// readHandshakeMessage returns one full handshake-layer message (header +
// body) regardless of record framing. It transparently:
//
//   - skips ChangeCipherSpec records (legacy middlebox compat, RFC 8446 §5)
//   - reassembles a handshake message split across multiple records
//   - returns successive messages packed in a single record one at a time
//
// Errors out if it encounters a non-handshake, non-CCS record while waiting
// for handshake bytes.
func (c *Conn) readHandshakeMessage() ([]byte, error) {
	for {
		if msg, ok := c.takeBufferedHandshake(); ok {
			return msg, nil
		}

		typ, plaintext, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		switch typ {
		case contentTypeChangeCipherSpec:
			continue
		case contentTypeHandshake:
			c.hsBuf = append(c.hsBuf, plaintext...)
		case contentTypeAlert:
			return nil, fmt.Errorf("tls: peer alert during handshake: % x", plaintext)
		default:
			return nil, fmt.Errorf("tls: expected handshake record, got type %d", typ)
		}
	}
}

// takeBufferedHandshake tries to slice one complete handshake message off
// the front of hsBuf. Returns ok=false if we don't yet have a full header
// or full body.
func (c *Conn) takeBufferedHandshake() ([]byte, bool) {
	if len(c.hsBuf) < handshakeHeaderLen {
		return nil, false
	}
	bodyLen := uint32(c.hsBuf[1])<<16 | uint32(c.hsBuf[2])<<8 | uint32(c.hsBuf[3])
	total := handshakeHeaderLen + int(bodyLen)
	if len(c.hsBuf) < total {
		return nil, false
	}
	msg := append([]byte(nil), c.hsBuf[:total]...)
	c.hsBuf = c.hsBuf[total:]
	return msg, true
}

// writePlaintextHandshake emits one handshake-typed record carrying msg.
// Used only for the initial ServerHello.
func (c *Conn) writePlaintextHandshake(msg []byte) error {
	return writeRecord(c.raw, contentTypeHandshake, msg)
}

// writeEncryptedHandshake emits one application_data record whose inner
// type is handshake — i.e. an encrypted handshake message. Used for every
// server-to-client message after ServerHello.
func (c *Conn) writeEncryptedHandshake(msg []byte) error {
	if c.writeKeys == nil {
		return errors.New("tls: writeEncryptedHandshake before AEAD active")
	}
	sealed, err := c.writeKeys.Seal(contentTypeHandshake, msg)
	if err != nil {
		return err
	}
	_, err = c.raw.Write(sealed)
	return err
}
