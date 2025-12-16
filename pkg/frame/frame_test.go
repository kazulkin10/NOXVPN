package frame

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	original := &Frame{
		Type:     TypeData,
		Flags:    1,
		StreamID: 42,
		Payload:  []byte("payload"),
	}

	encoded, err := EncodeFrame(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := ReadFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Type != original.Type || decoded.Flags != original.Flags || decoded.StreamID != original.StreamID {
		t.Fatalf("header mismatch: %+v vs %+v", decoded, original)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Fatalf("payload mismatch: %q vs %q", decoded.Payload, original.Payload)
	}
}
