package replay

import "testing"

func TestReplayWindow(t *testing.T) {
	w := New(8)
	for i := 0; i < 8; i++ {
		if !w.Check(uint64(i)) {
			t.Fatalf("fresh seq %d rejected", i)
		}
	}
	if w.Check(3) {
		t.Fatalf("duplicate not rejected")
	}
	if w.Check(0) {
		t.Fatalf("old seq not rejected")
	}
	if !w.Check(100) {
		t.Fatalf("far future seq rejected")
	}
}
