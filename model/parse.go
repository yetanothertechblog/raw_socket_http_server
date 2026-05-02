package model

import (
	"encoding/binary"
	"fmt"
)

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

/*
		Parse the TCP Segment
	 │ Bytes  │           Field                               │
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
