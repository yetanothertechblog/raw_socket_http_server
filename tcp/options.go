package tcp

import "encoding/binary"

// TCP option kinds per RFC 9293 §3.1.
const (
	optEnd = 0 // End of Option List
	optNOP = 1 // No-Operation (single-byte padding)
	optMSS = 2 // Maximum Segment Size (length 4)
)

// parseMSSOption iterates the TCP options block and returns the MSS value if
// present. Malformed or truncated options terminate parsing silently — we
// prefer falling back to the default MSS over dropping the whole segment.
func parseMSSOption(opts []byte) (uint16, bool) {
	i := 0
	for i < len(opts) {
		switch opts[i] {
		case optEnd:
			return 0, false
		case optNOP:
			i++
		default:
			if i+1 >= len(opts) {
				return 0, false
			}
			length := int(opts[i+1])
			if length < 2 || i+length > len(opts) {
				return 0, false
			}
			if opts[i] == optMSS && length == 4 {
				return binary.BigEndian.Uint16(opts[i+2 : i+4]), true
			}
			i += length
		}
	}
	return 0, false
}

// buildMSSOption returns a 4-byte TCP MSS option: [kind=2, len=4, hi, lo].
// Exactly 4 bytes, so no padding needed to maintain the 4-byte header alignment.
func buildMSSOption(mss uint16) []byte {
	return []byte{optMSS, 4, byte(mss >> 8), byte(mss)}
}
