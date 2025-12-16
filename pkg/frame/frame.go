package frame

const (
    FrameData  = 1
    FramePing  = 2
    FramePong  = 3
    FrameClose = 4
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
