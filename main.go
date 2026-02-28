package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

type EthernetFrame struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
	Payload   []byte
}

/*
		Parse the Ethernet Frame
	 │ Bytes │           Field           │
	 │ 0-5   │ Destination MAC address   │
	 │ 6-11  │ Source MAC address        │
	 │ 12-13 │ EtherType (what's inside) │
*/
func ParseEthernetFrame(buf []byte, n int) (EthernetFrame, error) {
	if n < 14 {
		return EthernetFrame{}, fmt.Errorf("frame too short: %d bytes", n)
	}

	var frame EthernetFrame
	copy(frame.DstMAC[:], buf[0:6])
	copy(frame.SrcMAC[:], buf[6:12])
	frame.EtherType = binary.BigEndian.Uint16(buf[12:14])
	frame.Payload = buf[14:n]

	return frame, nil
}

type IPv4Packet struct {
	Version  uint8
	IHL      uint8
	TotalLen uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    [4]byte
	DstIP    [4]byte
	Payload  []byte
}

func (e *EthernetFrame) flushToBytes() []byte {
	buf := make([]byte, 14+len(e.Payload))
	copy(buf[0:6], e.DstMAC[:])
	copy(buf[6:12], e.SrcMAC[:])
	binary.BigEndian.PutUint16(buf[12:14], e.EtherType)
	copy(buf[14:], e.Payload)
	return buf
}

type TCPSegment struct {
	SourcePort uint16
	DestPort   uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Reserved   uint8
	Flags      byte
	Window     uint16
	Checksum   uint16
	UrgPointer uint16
	Options    []byte
	Payload    []byte
}

func (p *IPv4Packet) flushToBytes() []byte {
	headerLen := int(p.IHL) * 4
	buf := make([]byte, headerLen+len(p.Payload))
	buf[0] = (p.Version << 4) | p.IHL
	buf[1] = 0 // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(headerLen+len(p.Payload)))
	binary.BigEndian.PutUint16(buf[4:6], 0) // Identification
	binary.BigEndian.PutUint16(buf[6:8], 0) // Flags + Fragment offset
	buf[8] = p.TTL
	buf[9] = p.Protocol
	binary.BigEndian.PutUint16(buf[10:12], 0) // Checksum (zero for calculation)
	copy(buf[12:16], p.SrcIP[:])
	copy(buf[16:20], p.DstIP[:])

	// Calculate header checksum
	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(buf[10:12], ^uint16(sum))

	copy(buf[headerLen:], p.Payload)
	return buf
}

/*
		Parse the IPv4 Packet
	 │ Bytes  │           Field                              │
	 │ 0 hi   │ Version (always 4)                           │
	 │ 0 lo   │ IHL (header length in 32-bit words)          │
	 │ 2-3    │ Total length                                 │
	 │ 8      │ TTL                                          │
	 │ 9      │ Protocol (1=ICMP, 6=TCP, 17=UDP)             │
	 │ 10-11  │ Header checksum                              │
	 │ 12-15  │ Source IP                                    │
	 │ 16-19  │ Destination IP                               │
*/
func ParseIPv4Packet(buf []byte) (IPv4Packet, error) {
	if len(buf) < 20 {
		return IPv4Packet{}, fmt.Errorf("IPv4 packet too short: %d bytes", len(buf))
	}

	var pkt IPv4Packet
	pkt.Version = buf[0] >> 4 // First byte contains <4 bits Version, 4 bits IHL>
	pkt.IHL = buf[0] & 0x0F

	pkt.TotalLen = binary.BigEndian.Uint16(buf[2:4]) // IP packets are big endian vs little endian on processors
	pkt.TTL = buf[8]
	pkt.Protocol = uint8(buf[9])
	pkt.Checksum = binary.BigEndian.Uint16(buf[10:12])
	copy(pkt.SrcIP[:], buf[12:16])
	copy(pkt.DstIP[:], buf[16:20])

	headerLen := int(pkt.IHL) * 4
	if len(buf) < headerLen {
		return IPv4Packet{}, fmt.Errorf("IPv4 header truncated: IHL=%d but only %d bytes", pkt.IHL, len(buf))
	}
	pkt.Payload = buf[headerLen:]

	return pkt, nil
}

func (t *TCPSegment) flushToBytes() []byte {
	headerLen := int(t.DataOffset) * 4
	buf := make([]byte, headerLen+len(t.Payload))
	binary.BigEndian.PutUint16(buf[0:2], t.SourcePort)
	binary.BigEndian.PutUint16(buf[2:4], t.DestPort)
	binary.BigEndian.PutUint32(buf[4:8], t.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], t.AckNum)
	buf[12] = (t.DataOffset << 4) | t.Reserved
	buf[13] = t.Flags
	binary.BigEndian.PutUint16(buf[14:16], t.Window)
	binary.BigEndian.PutUint16(buf[16:18], 0) // Checksum (calculated separately)
	binary.BigEndian.PutUint16(buf[18:20], t.UrgPointer)
	if len(t.Options) > 0 {
		copy(buf[20:headerLen], t.Options)
	}
	copy(buf[headerLen:], t.Payload)
	return buf
}

/*
		Parse the TCP Segment
	 │ Bytes  │           Field                              │
	 │ 0-1    │ Source port                                   │
	 │ 2-3    │ Destination port                              │
	 │ 4-7    │ Sequence number                               │
	 │ 8-11   │ Acknowledgment number                         │
	 │ 12 hi  │ Data offset (header length in 32-bit words)   │
	 │ 12 lo  │ Reserved                                      │
	 │ 13     │ Flags (SYN, ACK, FIN, RST, PSH, URG)          │
	 │ 14-15  │ Window size                                   │
	 │ 16-17  │ Checksum                                      │
	 │ 18-19  │ Urgent pointer                                │
*/
func ParseTCPSegment(buf []byte) (TCPSegment, error) {
	if len(buf) < 20 {
		return TCPSegment{}, fmt.Errorf("TCP segment too short: %d bytes", len(buf))
	}

	var seg TCPSegment
	seg.SourcePort = binary.BigEndian.Uint16(buf[0:2])
	seg.DestPort = binary.BigEndian.Uint16(buf[2:4])
	seg.SeqNum = binary.BigEndian.Uint32(buf[4:8])
	seg.AckNum = binary.BigEndian.Uint32(buf[8:12])
	seg.DataOffset = buf[12] >> 4
	seg.Reserved = buf[12] & 0x0F
	seg.Flags = buf[13]
	seg.Window = binary.BigEndian.Uint16(buf[14:16])
	seg.Checksum = binary.BigEndian.Uint16(buf[16:18])
	seg.UrgPointer = binary.BigEndian.Uint16(buf[18:20])

	headerLen := int(seg.DataOffset) * 4
	if len(buf) < headerLen {
		return TCPSegment{}, fmt.Errorf("TCP header truncated: offset=%d but only %d bytes", seg.DataOffset, len(buf))
	}
	if headerLen > 20 {
		seg.Options = buf[20:headerLen]
	}
	seg.Payload = buf[headerLen:]

	return seg, nil
}

/*
		ICMP Echo Header
	 │ Bytes │           Field           │
	 │ 0     │ Type (8=request, 0=reply) │
	 │ 1     │ Code (0)                  │
	 │ 2-3   │ Checksum                  │
	 │ 4-5   │ Identifier                │
	 │ 6-7   │ Sequence number           │
	 │ 8+    │ Data                      │
*/
func runICMPEchoServer() {
	fd, err := syscall.Socket(17, 3, 0x0300)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	buf := make([]byte, 1518)

	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			panic(err)
		}

		frame, err := ParseEthernetFrame(buf, n)
		if err != nil {
			continue
		}

		fmt.Printf("Frame: EtherType=%04x\n", frame.EtherType)
		// Only handle IPv4
		if frame.EtherType != 0x0800 {
			continue
		}

		pkt, err := ParseIPv4Packet(frame.Payload)
		if err != nil {
			fmt.Println("IPv4 parse error:", err)
			continue
		}
		fmt.Printf("IPv4: proto=%d src=%d.%d.%d.%d\n",
			pkt.Protocol, pkt.SrcIP[0], pkt.SrcIP[1], pkt.SrcIP[2], pkt.SrcIP[3])

		// Only handle ICMP (protocol 1)
		if pkt.Protocol != 1 {
			continue
		}

		icmp := pkt.Payload
		fmt.Printf("ICMP: type=%d code=%d len=%d\n", icmp[0], icmp[1], len(icmp))
		if len(icmp) < 8 {
			continue
		}

		// Only handle Echo Request (type 8)
		if icmp[0] != 8 {
			continue
		}

		fmt.Printf("ICMP Echo Request from %d.%d.%d.%d\n",
			pkt.SrcIP[0], pkt.SrcIP[1], pkt.SrcIP[2], pkt.SrcIP[3])

		// Build ICMP Echo Reply — change type from 8 to 0, recalculate checksum
		reply := make([]byte, len(icmp))
		copy(reply, icmp)
		reply[0] = 0 // Type 0 = Echo Reply
		reply[1] = 0 // Code 0
		reply[2] = 0 // Zero checksum for calculation
		reply[3] = 0

		var sum uint32
		for i := 0; i < len(reply)-1; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(reply[i : i+2]))
		}
		if len(reply)%2 == 1 {
			sum += uint32(reply[len(reply)-1]) << 8
		}
		for sum > 0xFFFF {
			sum = (sum >> 16) + (sum & 0xFFFF)
		}
		binary.BigEndian.PutUint16(reply[2:4], ^uint16(sum))

		// Build IPv4 response — swap src/dst
		responsePkt := IPv4Packet{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: 1,
			SrcIP:    pkt.DstIP,
			DstIP:    pkt.SrcIP,
			Payload:  reply,
		}

		// Build Ethernet response — swap src/dst MACs
		responseFrame := EthernetFrame{
			DstMAC:    frame.SrcMAC,
			SrcMAC:    frame.DstMAC,
			EtherType: 0x0800,
			Payload:   responsePkt.flushToBytes(),
		}

		rawBytes := responseFrame.flushToBytes()
		err = syscall.Sendto(fd, rawBytes, 0, from)
		if err != nil {
			fmt.Println("sendto error:", err)
		} else {
			fmt.Println("  -> Sent ICMP Echo Reply")
		}
	}
}

func main() {
	fmt.Println("Starting ICMP Echo Server...")
	runICMPEchoServer()
}
