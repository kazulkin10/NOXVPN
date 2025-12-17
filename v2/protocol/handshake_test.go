package protocol

import (
	"net"
	"testing"
)

// Integration-style stub: exercises HELLO -> ASSIGN using in-memory pipe without TUN.
func TestHelloAssignPipe(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan error, 1)
	go func() {
		hello := Hello{Capabilities: CapMTUNeg, DesiredMTU: 1400}
		payload := append([]byte{CtrlHello}, EncodeHello(hello)...)
		err := WriteRecord(c1, Frame{Version: Version, Kind: KindControl, Payload: payload})
		done <- err
	}()

	frame, err := ReadRecord(c2)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Kind != KindControl || frame.Payload[0] != CtrlHello {
		t.Fatalf("unexpected frame")
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
}
