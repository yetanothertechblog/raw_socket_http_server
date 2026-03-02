package tcp

import (
	"io"
	"syscall"
	"time"

	"github.com/http-server/m/model"
)

// unique identifier for a TCP connection (srcIP, srcPort, destIP, destPort)
type ConnectionKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
}

type TCPConnection struct {
	State           TCPState
	LocalIP         [4]byte
	LocalPort       uint16
	RemoteIP        [4]byte
	RemotePort      uint16
	SendSeqNum      uint32 // Next sequence number to send
	SendUnacked     uint32 // Oldest unacked sequence
	RecvSeqNum      uint32 // Next sequence number expected
	RecvWindow      uint16 // Advertised receive window
	SendWindow      uint16 // Peer's window size
	RecvBuffer      []byte // Received data (in-order)
	SendBuffer      []byte // Data to send (unacked)
	RetransmitTimer *time.Timer
	readCh          chan []byte // recv loop pushes data here, Read() blocks on it
	overflow        []byte      // leftover data that didn't fit in the caller's buf

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
	// Build a frame with the stored MACs so sendSegment can use it
	// TODO: We are not chunking the data currently, if the data spans multiple IP packets this will not work
	frame := &model.EthernetFrame{
		SrcMAC: c.remoteMAC, // sendSegment swaps these
		DstMAC: c.localMAC,
	}
	c.stack.sendSegment(c, PSH|ACK, data, frame, c.sockaddr)
	c.SendSeqNum += uint32(len(data))
	return len(data), nil
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
