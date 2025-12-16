package control

import (
"encoding/binary"
"errors"
"net"
)

const (
Magic0 = byte('N')
Magic1 = byte('X')

OpHello    = 1
OpAssignIP = 2
OpBeat     = 3
)

// format (all inside plaintext BEFORE crypto, i.e. encrypted over the wire):
// [0]='N' [1]='X' [2]=op [3..]=op-specific
//
// Hello:    op=1, payload: [8]session
// AssignIP: op=2, payload: [4]ip [1]maskbits
// Beat:     op=3, payload: [8]session (optional, but we keep it consistent)

func EncodeHello(session [8]byte) []byte {
b := make([]byte, 3+8)
b[0], b[1], b[2] = Magic0, Magic1, OpHello
copy(b[3:], session[:])
return b
}

func EncodeBeat(session [8]byte) []byte {
b := make([]byte, 3+8)
b[0], b[1], b[2] = Magic0, Magic1, OpBeat
copy(b[3:], session[:])
return b
}

func EncodeAssignIP(ip net.IP, maskBits int) ([]byte, error) {
ip4 := ip.To4()
if ip4 == nil {
return nil, errors.New("not ipv4")
}
b := make([]byte, 3+4+1)
b[0], b[1], b[2] = Magic0, Magic1, OpAssignIP
copy(b[3:7], ip4)
b[7] = byte(maskBits)
return b, nil
}

func Decode(b []byte) (op byte, rest []byte, ok bool) {
if len(b) < 3 || b[0] != Magic0 || b[1] != Magic1 {
return 0, nil, false
}
return b[2], b[3:], true
}

func DecodeSession(rest []byte) ([8]byte, bool) {
var s [8]byte
if len(rest) < 8 {
return s, false
}
copy(s[:], rest[:8])
return s, true
}

func DecodeAssignIP(rest []byte) (net.IP, int, bool) {
if len(rest) < 5 {
return nil, 0, false
}
ip := net.IPv4(rest[0], rest[1], rest[2], rest[3]).To4()
mask := int(rest[4])
return ip, mask, true
}

func Uint32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
