package crypto

import "testing"

func TestDeriveSessionKeys(t *testing.T) {
	master := make([]byte, 32)
	var sid [8]byte
	sid[0] = 1
	cn := make([]byte, 16)
	sn := make([]byte, 16)
	tx, rx, err := DeriveSessionKeys(master, sid, cn, sn, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tx) != 32 || len(rx) != 32 {
		t.Fatalf("bad key len")
	}
	tx2, rx2, err := DeriveSessionKeys(master, sid, cn, sn, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(tx) == string(tx2) || string(rx) == string(rx2) {
		t.Fatalf("keys should differ by role")
	}
}
