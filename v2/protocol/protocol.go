package protocol

import (
	"encoding/binary"
	"errors"
)

// Protocol constants.
const (
	Version uint8 = 0x02

	KindControl uint8 = 0x01
	KindData    uint8 = 0x02
)

// Capability flags advertised in HELLO.
const (
	CapIPv6        uint16 = 0x0001
	CapRekey       uint16 = 0x0002
	CapMTUNeg      uint16 = 0x0004
	CapQUIC        uint16 = 0x0008
	CapReplayGuard uint16 = 0x0010
)

// Control opcodes.
const (
	CtrlHello     uint8 = 0x01
	CtrlAssignIP  uint8 = 0x02
	CtrlRoutes    uint8 = 0x03
	CtrlHeartbeat uint8 = 0x04
	CtrlRekey     uint8 = 0x05
	CtrlClose     uint8 = 0x06
	CtrlError     uint8 = 0x07
)

// Frame is the common header for every record before encryption.
type Frame struct {
	Version uint8
	Kind    uint8
	Length  uint16 // length of payload
	Payload []byte
}

// Encode serialises the frame header plus payload.
func Encode(f Frame) ([]byte, error) {
	if f.Length != uint16(len(f.Payload)) {
		f.Length = uint16(len(f.Payload))
	}
	buf := make([]byte, 6+len(f.Payload))
	buf[0] = f.Version
	buf[1] = f.Kind
	binary.BigEndian.PutUint16(buf[2:], 0) // reserved
	binary.BigEndian.PutUint16(buf[4:], f.Length)
	copy(buf[6:], f.Payload)
	return buf, nil
}

// Decode parses a frame from a length-delimited record.
func Decode(data []byte) (Frame, error) {
	if len(data) < 6 {
		return Frame{}, errors.New("frame too short")
	}
	f := Frame{Version: data[0], Kind: data[1], Length: binary.BigEndian.Uint16(data[4:6])}
	if int(f.Length)+6 != len(data) {
		return Frame{}, errors.New("frame length mismatch")
	}
	f.Payload = data[6:]
	return f, nil
}

// Hello carries client capabilities and nonce.
type Hello struct {
	Capabilities uint16
	SessionID    [8]byte
	ClientNonce  [16]byte
	DesiredMTU   uint16
}

// AssignIP assigns IPv4 and negotiated MTU.
type AssignIP struct {
	SessionID   [8]byte
	IPv4        [4]byte
	PrefixLen   uint8
	MTU         uint16
	ServerNonce [16]byte
}

// Routes announces server-pushed routes.
type Routes struct {
	Nets []Route
}

// Route describes an IPv4 prefix.
type Route struct {
	Network [4]byte
	Prefix  uint8
}

// Heartbeat carries echo counter.
type Heartbeat struct {
	Echo uint32
}

// Rekey announces a new epoch and nonce.
type Rekey struct {
	Epoch uint32
	Nonce [16]byte
}

// Close notifies with a reason.
type Close struct {
	Code   uint16
	Reason string
}

// ErrorCode mirrors Close for negotiation failures.
type ErrorCode struct {
	Code   uint16
	Reason string
}

// EncodeHello returns TLV payload for HELLO.
func EncodeHello(h Hello) []byte {
	buf := make([]byte, 8+16+2+2)
	binary.BigEndian.PutUint16(buf[0:], h.Capabilities)
	copy(buf[2:10], h.SessionID[:])
	copy(buf[10:26], h.ClientNonce[:])
	binary.BigEndian.PutUint16(buf[26:], h.DesiredMTU)
	return buf
}

// DecodeHello parses HELLO payload.
func DecodeHello(p []byte) (Hello, error) {
	if len(p) != 28 {
		return Hello{}, errors.New("hello len")
	}
	var h Hello
	h.Capabilities = binary.BigEndian.Uint16(p[0:2])
	copy(h.SessionID[:], p[2:10])
	copy(h.ClientNonce[:], p[10:26])
	h.DesiredMTU = binary.BigEndian.Uint16(p[26:28])
	return h, nil
}

// EncodeAssign serialises AssignIP payload.
func EncodeAssign(a AssignIP) []byte {
	buf := make([]byte, 8+4+1+2+16)
	copy(buf[0:8], a.SessionID[:])
	copy(buf[8:12], a.IPv4[:])
	buf[12] = a.PrefixLen
	binary.BigEndian.PutUint16(buf[13:15], a.MTU)
	copy(buf[15:], a.ServerNonce[:])
	return buf
}

// DecodeAssign parses AssignIP payload.
func DecodeAssign(p []byte) (AssignIP, error) {
	if len(p) != 8+4+1+2+16 {
		return AssignIP{}, errors.New("assign len")
	}
	var a AssignIP
	copy(a.SessionID[:], p[0:8])
	copy(a.IPv4[:], p[8:12])
	a.PrefixLen = p[12]
	a.MTU = binary.BigEndian.Uint16(p[13:15])
	copy(a.ServerNonce[:], p[15:])
	return a, nil
}

// EncodeRoutes serialises route list.
func EncodeRoutes(r Routes) []byte {
	if len(r.Nets) > 255 {
		return nil
	}
	buf := make([]byte, 1+len(r.Nets)*5)
	buf[0] = byte(len(r.Nets))
	off := 1
	for _, n := range r.Nets {
		copy(buf[off:off+4], n.Network[:])
		buf[off+4] = n.Prefix
		off += 5
	}
	return buf
}

// DecodeRoutes parses Routes payload.
func DecodeRoutes(p []byte) (Routes, error) {
	if len(p) == 0 {
		return Routes{}, errors.New("routes len")
	}
	count := int(p[0])
	if len(p) != 1+count*5 {
		return Routes{}, errors.New("routes size")
	}
	rs := Routes{Nets: make([]Route, 0, count)}
	off := 1
	for i := 0; i < count; i++ {
		var rt Route
		copy(rt.Network[:], p[off:off+4])
		rt.Prefix = p[off+4]
		rs.Nets = append(rs.Nets, rt)
		off += 5
	}
	return rs, nil
}

// EncodeHeartbeat serialises HEARTBEAT.
func EncodeHeartbeat(h Heartbeat) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, h.Echo)
	return buf
}

// DecodeHeartbeat parses HEARTBEAT.
func DecodeHeartbeat(p []byte) (Heartbeat, error) {
	if len(p) != 4 {
		return Heartbeat{}, errors.New("heartbeat len")
	}
	return Heartbeat{Echo: binary.BigEndian.Uint32(p)}, nil
}

// EncodeRekey serialises REKEY.
func EncodeRekey(r Rekey) []byte {
	buf := make([]byte, 4+16)
	binary.BigEndian.PutUint32(buf[0:4], r.Epoch)
	copy(buf[4:], r.Nonce[:])
	return buf
}

// DecodeRekey parses REKEY.
func DecodeRekey(p []byte) (Rekey, error) {
	if len(p) != 20 {
		return Rekey{}, errors.New("rekey len")
	}
	var r Rekey
	r.Epoch = binary.BigEndian.Uint32(p[0:4])
	copy(r.Nonce[:], p[4:])
	return r, nil
}

// EncodeClose encodes CLOSE/ERROR reasons.
func EncodeClose(c Close) []byte {
	reason := []byte(c.Reason)
	if len(reason) > 255 {
		reason = reason[:255]
	}
	buf := make([]byte, 2+1+len(reason))
	binary.BigEndian.PutUint16(buf[0:2], c.Code)
	buf[2] = byte(len(reason))
	copy(buf[3:], reason)
	return buf
}

// DecodeClose parses CLOSE/ERROR payload.
func DecodeClose(p []byte) (Close, error) {
	if len(p) < 3 {
		return Close{}, errors.New("close len")
	}
	l := int(p[2])
	if len(p) != 3+l {
		return Close{}, errors.New("close size")
	}
	return Close{Code: binary.BigEndian.Uint16(p[0:2]), Reason: string(p[3:])}, nil
}
