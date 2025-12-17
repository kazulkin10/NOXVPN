package protocol

import "testing"

func TestEncodeDecodeFrame(t *testing.T) {
	f := Frame{Version: Version, Kind: KindControl, Payload: []byte{1, 2, 3}}
	raw, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != f.Version || out.Kind != f.Kind || len(out.Payload) != len(f.Payload) {
		t.Fatalf("mismatch")
	}
}

func TestHelloRoundtrip(t *testing.T) {
	var h Hello
	h.Capabilities = CapMTUNeg | CapReplayGuard
	h.SessionID[0] = 1
	h.ClientNonce[0] = 2
	h.DesiredMTU = 1400
	raw := EncodeHello(h)
	got, err := DecodeHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities != h.Capabilities || got.DesiredMTU != h.DesiredMTU {
		t.Fatalf("roundtrip failed")
	}
}
