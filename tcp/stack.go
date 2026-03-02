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
		accept: make(chan *TCPConnection),
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

	conn := &TCPConnection{
		State:       SYN_RECEIVED,
		LocalIP:     pkt.DstIP,
		LocalPort:   seg.DestPort,
		RemoteIP:    pkt.SrcIP,
		RemotePort:  seg.SourcePort,
		SendSeqNum:  isn,
		SendUnacked: isn,
		RecvSeqNum:  seg.SeqNum + 1, // SYN consumes one sequence number
		RecvWindow:  DefaultWindow,
		SendWindow:  seg.Window,
		readCh:      make(chan []byte, 16),
		localMAC:    frame.DstMAC,
		remoteMAC:   frame.SrcMAC,
		sockaddr:    from,
		stack:       s,
	}

	s.mu.Lock()
	s.connections[key] = conn
	s.mu.Unlock()

	// Send SYN+ACK
	s.sendSegment(conn, SYN|ACK, nil, frame, from)
	conn.SendSeqNum++ // SYN consumes one sequence number on our side too

}

func (s *Stack) handleSegment(conn *TCPConnection, seg *model.TCPSegment, pkt *model.IPv4Packet, frame *model.EthernetFrame, from syscall.Sockaddr) {
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

	case ESTABLISHED:
		// Handle incoming data
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
			close(conn.readCh) // unblock Read() with io.EOF
			fmt.Printf("FIN received, moving to CLOSE_WAIT\n")
		}

	case FIN_WAIT_1:
		// We sent FIN, waiting for ACK and/or FIN from remote
		if seg.Flags&ACK != 0 {
			conn.SendUnacked = seg.AckNum
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
