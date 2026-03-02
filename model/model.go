package model

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

type EthernetFrame struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
	Payload   []byte
}
