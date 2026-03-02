package icmp

import (
	"encoding/binary"
	"fmt"
	"syscall"

	model "github.com/http-server/m/model"
)

func RunICMPEchoServer() {
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

		frame, err := model.ParseEthernetFrame(buf, n)
		if err != nil {
			continue
		}

		fmt.Printf("Frame: EtherType=%04x\n", frame.EtherType)
		// Only handle IPv4
		if frame.EtherType != 0x0800 {
			continue
		}

		pkt, err := model.ParseIPv4Packet(frame.Payload)
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
		responsePkt := model.IPv4Packet{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: 1,
			SrcIP:    pkt.DstIP,
			DstIP:    pkt.SrcIP,
			Payload:  reply,
		}

		// Build Ethernet response — swap src/dst MACs
		responseFrame := model.EthernetFrame{
			DstMAC:    frame.SrcMAC,
			SrcMAC:    frame.DstMAC,
			EtherType: 0x0800,
			Payload:   responsePkt.FlushToBytes(),
		}

		rawBytes := responseFrame.FlushToBytes()
		err = syscall.Sendto(fd, rawBytes, 0, from)
		if err != nil {
			fmt.Println("sendto error:", err)
		} else {
			fmt.Println("  -> Sent ICMP Echo Reply")
		}
	}
}
