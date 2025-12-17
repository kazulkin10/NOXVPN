package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteRecord writes a length-prefixed frame to w.
func WriteRecord(w io.Writer, f Frame) error {
	raw, err := Encode(f)
	if err != nil {
		return err
	}
	if len(raw) > 65535 {
		return fmt.Errorf("frame too large")
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(raw)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// ReadRecord reads a length-prefixed frame.
func ReadRecord(r io.Reader) (Frame, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return Frame{}, err
	}
	size := binary.BigEndian.Uint16(lenBuf)
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Frame{}, err
	}
	return Decode(raw)
}
