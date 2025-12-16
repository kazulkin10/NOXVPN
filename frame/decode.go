package frame

import (
    "encoding/binary"
    "errors"
    "io"
)

func ReadFrame(r io.Reader) (*Frame, error) {
    // Читаем total_len
    header := make([]byte, 4)
    if _, err := io.ReadFull(r, header); err != nil {
        return nil, err
    }

    totalLen := binary.BigEndian.Uint32(header)
    if totalLen < 10 { // минимальный размер: 4+1+1+4
        return nil, errors.New("invalid total length")
    }

    // Читаем остальное
    body := make([]byte, totalLen-4)
    if _, err := io.ReadFull(r, body); err != nil {
        return nil, err
    }

    f := &Frame{}
    f.Type = body[0]
    f.Flags = body[1]
    f.StreamID = binary.BigEndian.Uint32(body[2:6])
    f.Payload = body[6:]

    return f, nil
}
