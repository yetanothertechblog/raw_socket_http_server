package tcp

import (
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/http-server/m/model"
)

// Network Stack - This struct is the "core" of the logic to move from raw Ethernet frames to TCP connections
type Stack struct {
	fd          int
	connections map[ConnectionKey]*TCPConnection
	mu          sync.RWMutex
	listeners   map[uint16]*Listener
}

// Once the TCP State moves to Established -> We pass to the Listener
type Listener struct {
	port   uint16
	accept chan *TCPConnection
}

func NewStack(fd int) *Stack {
	s := &Stack{
		fd:          fd,
		connections: make(map[ConnectionKey]*TCPConnection),
		listeners:   make(map[uint16]*Listener),
	}
	go s.recvLoop()
	return s
}

func (s *Stack) Listen(port uint16) *Listener {
	l := &Listener{
		port:   port,
		accept: make(chan *TCPConnection, 16),
	}
	s.mu.Lock()
	s.listeners[port] = l
	s.mu.Unlock()
	return l
}

func (l *Listener) Accept() *TCPConnection {
	return <-l.accept
}

func (s *Stack) recvLoop() {
	buf := make([]byte, 1518)
	for {
		n, from, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			continue
		}
		s.handleRaw(buf[:n], from)
	}
}

func (s *Stack) handleRaw(data []byte, from syscall.Sockaddr) {
	// Layer 2: Ethernet
	frame, err := model.ParseEthernetFrame(data, len(data))
	if err != nil {
		return
	}
	if frame.EtherType != 0x0800 { // only IPv4
		return
	}

	// Layer 3: IPv4
	pkt, err := model.ParseIPv4Packet(frame.Payload)
	if err != nil {
		return
	}
	if pkt.Protocol != 6 { // only TCP
		return
	}

	// Layer 4: TCP
	seg, err := model.ParseTCPSegment(pkt.Payload)
	if err != nil {
		return
	}

	// Build the 4-tuple key (from the remote's perspective: their src is our dst)
	key := ConnectionKey{
		SrcIP:   pkt.SrcIP,
		SrcPort: seg.SourcePort,
		DstIP:   pkt.DstIP,
		DstPort: seg.DestPort,
	}

	// Look up existing connection
	s.mu.RLock()
	conn, exists := s.connections[key]
	s.mu.RUnlock()

	if exists {
		s.handleSegment(conn, &seg, &pkt, &frame, from)
		return
	}

	// No existing connection — check if this is a SYN to a listening port
	s.mu.RLock()
	_, listening := s.listeners[seg.DestPort]
	s.mu.RUnlock()

	if !listening {
		// TODO: send RST
		return
	}

	if seg.Flags&0x02 == 0 { // not a SYN
		return
	} else {
		fmt.Printf("SYN received from %d.%d.%d.%d:%d\n",
			pkt.SrcIP[0], pkt.SrcIP[1], pkt.SrcIP[2], pkt.SrcIP[3], seg.SourcePort)
		handleSYN(&pkt, &seg, &frame, s, key, from)
	}

}

func handleSYN(pkt *model.IPv4Packet, seg *model.TCPSegment, frame *model.EthernetFrame, s *Stack, key ConnectionKey, from syscall.Sockaddr) {
	// Create new connection in SYN_RECEIVED state
	isn := generateISN()

	// Negotiate MSS per RFC 9293 §3.7.1: our send ceiling is the minimum of the
	// peer's advertised MSS and our own. Fall back to defaultMSS (536) if the
	// peer did not advertise an MSS option.
	peerMSS := defaultMSS
	if m, ok := parseMSSOption(seg.Options); ok {
		peerMSS = m
	}
	effectiveMSS := peerMSS
	if ourMSS < effectiveMSS {
		effectiveMSS = ourMSS
	}

	conn := &TCPConnection{
		State:       SYN_RECEIVED,
		LocalIP:     pkt.DstIP,
		LocalPort:   seg.DestPort,
		RemoteIP:    pkt.SrcIP,
		RemotePort:  seg.SourcePort,
		ISS:         isn,
		SendSeqNum:  isn,
		SendUnacked: isn,
		RecvSeqNum:  seg.SeqNum + 1, // SYN consumes one sequence number
		RecvWindow:  DefaultWindow,
		SendWindow:  seg.Window,
		WL1:         seg.SeqNum, // SEG.SEQ of the SYN that set our send window
		WL2:         seg.AckNum, // SYN carries no meaningful ACK; will be overwritten on first real ACK
		MSS:         effectiveMSS,
		readCh:      make(chan []byte, 16),
		localMAC:    frame.DstMAC,
		remoteMAC:   frame.SrcMAC,
		sockaddr:    from,
		stack:       s,
	}

	s.mu.Lock()
	s.connections[key] = conn
	s.mu.Unlock()

	// Send SYN+ACK with our own MSS advertisement. We announce ourMSS (our
	// receive ceiling), not effectiveMSS — the peer applies the same min()
	// logic on their side to pick their send ceiling.
	s.sendSegmentAt(conn, SYN|ACK, nil, conn.SendSeqNum, buildMSSOption(ourMSS), frame, from)
	conn.SendSeqNum++ // SYN consumes one sequence number on our side too

}

// processAck applies the ACK half of RFC 9293 §3.10.7.4 for synchronized
// states that share ESTABLISHED-style semantics (ESTABLISHED, FIN_WAIT_1,
// FIN_WAIT_2, CLOSE_WAIT). Returns false if the caller should drop the
// segment and stop further processing (challenge ACK already emitted when
// relevant). Returns true when the caller should continue processing the
// segment's payload / FIN.
//
// States with divergent semantics (SYN_RECEIVED expects RST on invalid ACK;
// CLOSING / LAST_ACK care specifically whether the FIN was acked) do not use
// this helper.
func (s *Stack) processAck(conn *TCPConnection, seg *model.TCPSegment, frame *model.EthernetFrame, from syscall.Sockaddr) bool {
	if seg.Flags&ACK == 0 {
		return false
	}

	conn.mu.Lock()
	if seqGT(seg.AckNum, conn.SendSeqNum) {
		// ACK for data we haven't sent — challenge ACK, drop segment.
		conn.mu.Unlock()
		s.sendSegment(conn, ACK, nil, frame, from)
		return false
	}
	if seqGT(seg.AckNum, conn.SendUnacked) {
		// New ACK — advance SND.UNA.
		conn.SendUnacked = seg.AckNum

		// Drain fully-acked segments from the retransmit queue.
		for len(conn.sendQueue) > 0 {
			head := conn.sendQueue[0]
			endSeq := head.seqNum + uint32(len(head.data))
			if seqLE(endSeq, seg.AckNum) {
				conn.sendQueue = conn.sendQueue[1:]
			} else {
				break
			}
		}

		// Timer management per RFC 6298 §5.2 / §5.3.
		if len(conn.sendQueue) == 0 {
			conn.stopRTOLocked()
		} else {
			conn.restartRTOLocked()
		}

		// SND.WND update rule: only trust fresher segments (§3.10.7.4).
		if seqLT(conn.WL1, seg.SeqNum) ||
			(conn.WL1 == seg.SeqNum && seqLE(conn.WL2, seg.AckNum)) {
			conn.SendWindow = seg.Window
			conn.WL1 = seg.SeqNum
			conn.WL2 = seg.AckNum
		}

		// The drain freed in-flight bytes and the window update may have grown
		// SND.WND — either way there may now be room to transmit buffered data.
		conn.pumpSendLocked()
	}
	// else: duplicate ACK (SEG.ACK <= SND.UNA) — ignore, continue.
	conn.mu.Unlock()
	return true
}

// abortConnection tears down a connection immediately (RST received or local
// abort). Moves to CLOSED, stops the RTO timer, drops all buffered send data,
// unblocks any pending Read with EOF, and removes from the connection map.
func (s *Stack) abortConnection(conn *TCPConnection) {
	conn.mu.Lock()
	if conn.State == CLOSED {
		conn.mu.Unlock()
		return
	}
	conn.State = CLOSED
	conn.stopRTOLocked()
	conn.sendQueue = nil
	conn.sendUnsent = nil
	conn.closeReadChLocked()
	conn.mu.Unlock()

	fmt.Printf("Connection aborted: %d.%d.%d.%d:%d\n",
		conn.RemoteIP[0], conn.RemoteIP[1], conn.RemoteIP[2], conn.RemoteIP[3], conn.RemotePort)

	key := ConnectionKey{
		SrcIP:   conn.RemoteIP,
		SrcPort: conn.RemotePort,
		DstIP:   conn.LocalIP,
		DstPort: conn.LocalPort,
	}
	s.mu.Lock()
	delete(s.connections, key)
	s.mu.Unlock()
}

func (s *Stack) handleSegment(conn *TCPConnection, seg *model.TCPSegment, pkt *model.IPv4Packet, frame *model.EthernetFrame, from syscall.Sockaddr) {
	// RST handling per RFC 9293 §3.10.7. Accept only when SEG.SEQ matches
	// RCV.NXT — out-of-window RSTs are ignored. RFC 5961 challenge-ACK for the
	// "in window but not expected" case is deferred.
	if seg.Flags&RST != 0 {
		if seg.SeqNum == conn.RecvSeqNum {
			s.abortConnection(conn)
		}
		return
	}

	switch conn.State {
	case SYN_RECEIVED:
		// Expecting ACK to complete the 3-way handshake
		if seg.Flags&ACK == 0 {
			return
		}
		conn.State = ESTABLISHED
		conn.SendUnacked = seg.AckNum
		conn.SendWindow = seg.Window

		fmt.Printf("Connection ESTABLISHED with %d.%d.%d.%d:%d\n",
			conn.RemoteIP[0], conn.RemoteIP[1], conn.RemoteIP[2], conn.RemoteIP[3], conn.RemotePort)

		// Push to listener's accept channel
		s.mu.RLock()
		l, ok := s.listeners[conn.LocalPort]
		s.mu.RUnlock()
		if ok {
			l.accept <- conn
		}

		// The same segment may carry piggybacked data and/or FIN — fall
		// through to ESTABLISHED handling so we don't drop bytes that
		// arrived on the third leg of the handshake. TLS clients (curl,
		// Go stdlib) routinely combine the ACK with the first record.
		fallthrough

	case ESTABLISHED:
		if !s.processAck(conn, seg, frame, from) {
			return
		}

		// Handle incoming data
		// TODO: handle out-of-order segments — currently we only accept in-order data
		// and silently drop anything that doesn't match RecvSeqNum
		// TODO: handle out-of-order segments — currently we only accept in-order data
		// and silently drop anything that doesn't match RecvSeqNum
		if len(seg.Payload) > 0 && seg.SeqNum == conn.RecvSeqNum {
			conn.RecvBuffer = append(conn.RecvBuffer, seg.Payload...)
			conn.RecvSeqNum += uint32(len(seg.Payload))

			// ACK the data
			s.sendSegment(conn, ACK, nil, frame, from)

			// Push to application
			data := make([]byte, len(conn.RecvBuffer))
			copy(data, conn.RecvBuffer)
			conn.RecvBuffer = conn.RecvBuffer[:0]
			conn.readCh <- data
		}
		// Handle FIN from remote — they want to close
		if seg.Flags&FIN != 0 {
			conn.RecvSeqNum++ // FIN consumes one sequence number
			conn.State = CLOSE_WAIT
			s.sendSegment(conn, ACK, nil, frame, from)
			conn.mu.Lock()
			conn.closeReadChLocked() // unblock Read() with io.EOF
			conn.mu.Unlock()
			fmt.Printf("FIN received, moving to CLOSE_WAIT\n")
		}

	case FIN_WAIT_1:
		// We sent FIN, waiting for ACK and/or FIN from remote
		if !s.processAck(conn, seg, frame, from) {
			return
		}
		if seg.Flags&FIN != 0 {
			conn.RecvSeqNum++
			s.sendSegment(conn, ACK, nil, frame, from)
			if seg.Flags&ACK != 0 {
				// ACK+FIN together — go straight to TIME_WAIT
				conn.State = TIME_WAIT
				fmt.Printf("FIN+ACK received in FIN_WAIT_1, moving to TIME_WAIT\n")
				go s.timeWaitCleanup(conn)
			} else {
				// Simultaneous close — only FIN, no ACK for ours yet
				conn.State = CLOSING
				fmt.Printf("Simultaneous close, moving to CLOSING\n")
			}
		} else if seg.Flags&ACK != 0 {
			// Only ACK for our FIN, still waiting for their FIN
			conn.State = FIN_WAIT_2
			fmt.Printf("ACK for our FIN, moving to FIN_WAIT_2\n")
		}

	case FIN_WAIT_2:
		// Waiting for remote's FIN
		if seg.Flags&FIN != 0 {
			conn.RecvSeqNum++
			s.sendSegment(conn, ACK, nil, frame, from)
			conn.State = TIME_WAIT
			fmt.Printf("FIN received, moving to TIME_WAIT\n")
			go s.timeWaitCleanup(conn)
		}

	case CLOSING:
		// Simultaneous close — waiting for ACK of our FIN
		if seg.Flags&ACK != 0 {
			conn.State = TIME_WAIT
			fmt.Printf("ACK received in CLOSING, moving to TIME_WAIT\n")
			go s.timeWaitCleanup(conn)
		}

	case LAST_ACK:
		// We sent FIN from CLOSE_WAIT, waiting for final ACK
		if seg.Flags&ACK != 0 {
			conn.State = CLOSED
			s.removeConnection(conn)
			fmt.Printf("Final ACK received, connection closed\n")
		}
	}
}

func (s *Stack) removeConnection(conn *TCPConnection) {
	conn.mu.Lock()
	conn.stopRTOLocked()
	conn.sendQueue = nil
	conn.sendUnsent = nil
	conn.mu.Unlock()

	key := ConnectionKey{
		SrcIP:   conn.RemoteIP,
		SrcPort: conn.RemotePort,
		DstIP:   conn.LocalIP,
		DstPort: conn.LocalPort,
	}
	s.mu.Lock()
	delete(s.connections, key)
	s.mu.Unlock()
}

func (s *Stack) timeWaitCleanup(conn *TCPConnection) {
	time.Sleep(2 * time.Second) // simplified 2MSL
	conn.State = CLOSED
	s.removeConnection(conn)
	fmt.Printf("TIME_WAIT expired, connection cleaned up\n")
}
