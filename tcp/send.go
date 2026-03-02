package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"syscall"

	"github.com/http-server/m/model"
)

const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10

	DefaultWindow = 65535
)

// calculateTCPChecksum computes the TCP checksum using the pseudo-header.
// The checksum field in tcpSegment must be zeroed before calling this.
func calculateTCPChecksum(srcIP, dstIP [4]byte, tcpSegment []byte) uint16 {
	// Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + protocol(1) + tcpLen(2) = 12 bytes
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = 6 // TCP protocol number
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpSegment)))

	var sum uint32
	for i := 0; i < len(pseudo)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(tcpSegment)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSegment[i : i+2]))
	}
	if len(tcpSegment)%2 == 1 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// Initial Sequence number
func generateISN() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32-1))
	if err != nil {
		return 1
	}
	return uint32(n.Uint64())
}

// sendSegment builds a full Ethernet → IPv4 → TCP packet and sends it on the wire.
// It computes the TCP checksum before sending.
func (s *Stack) sendSegment(conn *TCPConnection, flags byte, payload []byte, inFrame *model.EthernetFrame, from syscall.Sockaddr) {
	seg := model.TCPSegment{
		SourcePort: conn.LocalPort,
		DestPort:   conn.RemotePort,
		SeqNum:     conn.SendSeqNum,
		AckNum:     conn.RecvSeqNum,
		DataOffset: 5, // 20 bytes, no options
		Flags:      flags,
		Window:     conn.RecvWindow,
		Payload:    payload,
	}

	tcpBytes := seg.FlushToBytes()

	// Set the checksum
	checksum := calculateTCPChecksum(conn.LocalIP, conn.RemoteIP, tcpBytes)
	binary.BigEndian.PutUint16(tcpBytes[16:18], checksum)

	pkt := model.IPv4Packet{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: 6,
		SrcIP:    conn.LocalIP,
		DstIP:    conn.RemoteIP,
		Payload:  tcpBytes,
	}

	frame := model.EthernetFrame{
		DstMAC:    inFrame.SrcMAC, // reply to sender
		SrcMAC:    inFrame.DstMAC,
		EtherType: 0x0800,
		Payload:   pkt.FlushToBytes(),
	}

	syscall.Sendto(s.fd, frame.FlushToBytes(), 0, from)
}
