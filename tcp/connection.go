package tcp

import (
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/http-server/m/model"
)

// RFC 6298 timer bounds. Initial RTO is 1 second per §2.1. Exponential backoff
// per §5.5 caps at maxRTO (spec MAY, MUST be ≥ 60s).
const (
	initialRTO = 1 * time.Second
	maxRTO     = 60 * time.Second
)

// MSS constants per RFC 9293 §3.7.1.
//
//   - defaultMSS is the conservative fallback used when the peer does not
//     advertise an MSS option in its SYN.
//   - ourMSS is what we advertise in our SYN-ACK, assuming an Ethernet MTU of
//     1500 (1500 − 20 IPv4 − 20 TCP). No IP/TCP options accounted for.
const (
	defaultMSS uint16 = 536
	ourMSS     uint16 = 1460
)

// unique identifier for a TCP connection (srcIP, srcPort, destIP, destPort)
type ConnectionKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
}

// sentSegment is a record of a segment sent but not yet acknowledged.
// Retained on the send queue for retransmission until SND.UNA passes its end.
type sentSegment struct {
	seqNum uint32
	data   []byte
	flags  byte
}

type TCPConnection struct {
	// mu guards State, the send sequence variables, sendQueue, rto and rtoTimer.
	// Held by Write (app goroutine), processAck (recv goroutine), and onRTO (timer goroutine).
	mu sync.Mutex

	State      TCPState
	LocalIP    [4]byte
	LocalPort  uint16
	RemoteIP   [4]byte
	RemotePort uint16

	// RFC 9293 §3.3.1 send sequence variables
	ISS         uint32 // Initial send sequence number
	SendSeqNum  uint32 // SND.NXT — next sequence number to send
	SendUnacked uint32 // SND.UNA — oldest unacknowledged sequence
	SendWindow  uint16 // SND.WND — peer's advertised window
	WL1         uint32 // SND.WL1 — SEG.SEQ of last window update
	WL2         uint32 // SND.WL2 — SEG.ACK of last window update

	RecvSeqNum uint32 // RCV.NXT — next sequence number expected
	RecvWindow uint16 // RCV.WND — our advertised receive window
	RecvBuffer []byte // Received data (in-order)

	// MSS is the agreed send-side Maximum Segment Size for this connection:
	// min(peer's advertised MSS, ourMSS). Used to chunk Write into segments
	// that fit the path MTU without IP fragmentation. Initialized to defaultMSS
	// and overwritten in handleSYN once we parse the peer's MSS option.
	MSS uint16

	// sendUnsent holds application data that has been handed to Write but not
	// yet placed in a segment. Data leaves this buffer only as SND.WND permits.
	sendUnsent []byte

	// Retransmission state (RFC 6298). sendQueue holds segments sent but not yet
	// acked; rtoTimer fires on the head of queue; rto is the current retransmission
	// timeout, doubled on each expiry up to maxRTO.
	sendQueue []sentSegment
	rto       time.Duration
	rtoTimer  *time.Timer

	readCh       chan []byte // recv loop pushes data here, Read() blocks on it
	readChClosed bool        // guarded by mu; prevents double-close on FIN/RST races
	overflow     []byte      // leftover data that didn't fit in the caller's buf

	// Stored so we can send from the application goroutine without an incoming frame
	localMAC  [6]byte
	remoteMAC [6]byte
	sockaddr  syscall.Sockaddr
	stack     *Stack
}

func (c *TCPConnection) Read(buf []byte) (int, error) {
	// Drain overflow from a previous Read that didn't fit
	if len(c.overflow) > 0 {
		n := copy(buf, c.overflow)
		c.overflow = c.overflow[n:]
		return n, nil
	}

	data, ok := <-c.readCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(buf, data)
	if n < len(data) {
		c.overflow = data[n:]
	}
	return n, nil
}

func (c *TCPConnection) Close() {
	frame := &model.EthernetFrame{
		SrcMAC: c.remoteMAC,
		DstMAC: c.localMAC,
	}
	c.stack.sendSegment(c, FIN|ACK, nil, frame, c.sockaddr)
	c.SendSeqNum++ // FIN consumes one sequence number

	if c.State == ESTABLISHED {
		c.State = FIN_WAIT_1
	} else if c.State == CLOSE_WAIT {
		c.State = LAST_ACK
	}
}

func (c *TCPConnection) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Append to the unsent buffer, then transmit as much as the send window
	// currently allows. The rest stays buffered and drains on future ACKs.
	// Copy once at the boundary so the caller can reuse their slice.
	buf := make([]byte, len(data))
	copy(buf, data)
	c.sendUnsent = append(c.sendUnsent, buf...)

	c.pumpSendLocked()
	return len(data), nil
}

// pumpSendLocked emits chunks from sendUnsent as long as:
//   - SND.WND has room (in-flight bytes < peer's advertised window), and
//   - there is data in sendUnsent.
//
// Each chunk is at most MSS bytes. PSH is set on a chunk only if it drains
// sendUnsent completely in this pump cycle — a best-effort hint that a logical
// push boundary was reached. Caller must hold c.mu.
func (c *TCPConnection) pumpSendLocked() {
	mss := int(c.MSS)
	if mss == 0 {
		mss = int(defaultMSS)
	}

	frame := &model.EthernetFrame{
		SrcMAC: c.remoteMAC, // sendSegment swaps these
		DstMAC: c.localMAC,
	}

	sentAny := false
	for len(c.sendUnsent) > 0 {
		// Bytes currently in flight = SND.NXT − SND.UNA. uint32 subtraction
		// wraps correctly in the healthy case (difference is always <= 2^31).
		inFlight := c.SendSeqNum - c.SendUnacked
		if inFlight >= uint32(c.SendWindow) {
			break // peer's window is full; wait for ACK to reopen
		}
		avail := uint32(c.SendWindow) - inFlight

		chunkSize := mss
		if uint32(chunkSize) > avail {
			chunkSize = int(avail)
		}
		if chunkSize > len(c.sendUnsent) {
			chunkSize = len(c.sendUnsent)
		}
		if chunkSize == 0 {
			break
		}

		// Copy the chunk so the retransmit queue owns its own storage — we
		// reslice sendUnsent as we consume it.
		chunk := make([]byte, chunkSize)
		copy(chunk, c.sendUnsent[:chunkSize])
		c.sendUnsent = c.sendUnsent[chunkSize:]

		flags := byte(ACK)
		if len(c.sendUnsent) == 0 {
			flags |= PSH
		}

		seqNum := c.SendSeqNum
		c.sendQueue = append(c.sendQueue, sentSegment{
			seqNum: seqNum,
			data:   chunk,
			flags:  flags,
		})
		c.stack.sendSegmentAt(c, flags, chunk, seqNum, nil, frame, c.sockaddr)
		c.SendSeqNum += uint32(chunkSize)
		sentAny = true
	}

	// RFC 6298 §5.1: if we actually transmitted something, start timer if idle.
	if sentAny {
		c.startRTOIfIdleLocked()
	}
}

// startRTOIfIdleLocked arms the retransmission timer only if it is not
// currently scheduled (RFC 6298 §5.1). Caller must hold c.mu.
func (c *TCPConnection) startRTOIfIdleLocked() {
	if c.rtoTimer != nil {
		return
	}
	if c.rto == 0 {
		c.rto = initialRTO
	}
	c.rtoTimer = time.AfterFunc(c.rto, c.onRTO)
}

// restartRTOLocked reschedules the timer for c.rto from now (RFC 6298 §5.3:
// called when new data is acked but outstanding data remains). Caller must
// hold c.mu.
func (c *TCPConnection) restartRTOLocked() {
	if c.rto == 0 {
		c.rto = initialRTO
	}
	if c.rtoTimer == nil {
		c.rtoTimer = time.AfterFunc(c.rto, c.onRTO)
		return
	}
	c.rtoTimer.Reset(c.rto)
}

// closeReadChLocked closes readCh exactly once so Read() returns EOF. Safe to
// call from any close/abort path. Caller must hold c.mu.
func (c *TCPConnection) closeReadChLocked() {
	if c.readChClosed {
		return
	}
	close(c.readCh)
	c.readChClosed = true
}

// stopRTOLocked cancels the retransmission timer (RFC 6298 §5.2: called when
// all outstanding data has been acked). Caller must hold c.mu.
func (c *TCPConnection) stopRTOLocked() {
	if c.rtoTimer != nil {
		c.rtoTimer.Stop()
		c.rtoTimer = nil
	}
	c.rto = initialRTO // reset backoff so the next send starts fresh
}

// onRTO runs when the single retransmission timer expires (RFC 6298 §5.4–5.6).
// It retransmits the earliest unacked segment (head of queue), doubles the RTO
// up to maxRTO, and rearms. There is only ever one timer per connection — this
// function handles whichever segment happens to be at the head now.
func (c *TCPConnection) onRTO() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.sendQueue) == 0 {
		// Raced with an ACK that drained the queue between timer fire and lock.
		return
	}

	// §5.5: exponential backoff.
	c.rto *= 2
	if c.rto > maxRTO {
		c.rto = maxRTO
	}

	// §5.4: retransmit the earliest unacked segment with its original SEQ.
	head := c.sendQueue[0]
	frame := &model.EthernetFrame{
		SrcMAC: c.remoteMAC,
		DstMAC: c.localMAC,
	}
	c.stack.sendSegmentAt(c, head.flags, head.data, head.seqNum, nil, frame, c.sockaddr)

	// §5.6: restart the timer with the new (backed-off) RTO.
	c.rtoTimer.Reset(c.rto)
}

type TCPState int

const (
	CLOSED TCPState = iota
	LISTEN
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
	FIN_WAIT_1
	FIN_WAIT_2
	CLOSING
	TIME_WAIT
	CLOSE_WAIT
	LAST_ACK
)
