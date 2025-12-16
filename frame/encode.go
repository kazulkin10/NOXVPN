package frame

import (
    "bytes"
    "encoding/binary"
)

func EncodeFrame(f *Frame) ([]byte, error) {
    // total_len = 4(len) + 1(type) + 1(flags) + 4(streamID) + len(payload)
    totalLen := 4 + 1 + 1 + 4 + len(f.Payload)

    buf := new(bytes.Buffer)

    // 1) total_len
    binary.Write(buf, binary.BigEndian, uint32(totalLen))

    // 2) frame_type
    buf.WriteByte(f.Type)

    // 3) flags
    buf.WriteByte(f.Flags)

    // 4) stream_id
    binary.Write(buf, binary.BigEndian, f.StreamID)

    // 5) payload
    buf.Write(f.Payload)

    return buf.Bytes(), nil
}
