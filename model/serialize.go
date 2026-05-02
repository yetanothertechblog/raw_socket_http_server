package model

import (
	"encoding/binary"
)

func (e *EthernetFrame) FlushToBytes() []byte {
	buf := make([]byte, 14+len(e.Payload))
	copy(buf[0:6], e.DstMAC[:])
	copy(buf[6:12], e.SrcMAC[:])
	binary.BigEndian.PutUint16(buf[12:14], e.EtherType)
	copy(buf[14:], e.Payload)
	return buf
}

func (p *IPv4Packet) FlushToBytes() []byte {
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

func (t *TCPSegment) FlushToBytes() []byte {
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
