package frame

const (
	TypeData    uint8 = 1
	TypeControl uint8 = 2
	TypePing    uint8 = 3
	TypePong    uint8 = 4
	TypeClose   uint8 = 5
)

const (
	FrameData    = TypeData
	FramePing    = TypePing
	FramePong    = TypePong
	FrameClose   = TypeClose
	FrameControl = TypeControl
)

const (
	CtrlAssignIP  = 0x01
	CtrlReleaseIP = 0x02
	CtrlHeartbeat = 0x03
	CtrlHello     = 0x04 // client -> server: payload[1:9]=SessionID (8 bytes)
)

// Базовая структура кадра NOX (совместима с encode.go / decode.go)
type Frame struct {
	Type     uint8
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// Вспомогательный конструктор для "зашифрованного" кадра
func NewEncryptedFrame(ftype uint8, streamID uint32, cipherPayload []byte) *Frame {
	return &Frame{
		Type:     ftype,
		Flags:    0,
		StreamID: streamID,
		Payload:  cipherPayload,
	}
}
