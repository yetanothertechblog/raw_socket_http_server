package tcp

// Sequence number comparisons per RFC 9293 §3.4.
// Sequence numbers are unsigned 32-bit values that wrap around. The signed-
// difference idiom below returns the correct ordering as long as the two
// operands are within 2^31 of each other — which they always are during a
// healthy connection, since no more than 2 GiB of data can be in flight.

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }
