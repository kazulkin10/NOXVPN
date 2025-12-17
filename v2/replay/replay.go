package replay

import "sync"

// Window implements a sliding window replay detector.
type Window struct {
	mu     sync.Mutex
	maxSeq uint64
	window uint64
	seen   uint64
}

// New returns a replay window with a given size (<=64).
func New(size uint64) *Window {
	if size == 0 || size > 64 {
		size = 64
	}
	return &Window{window: size}
}

// Check returns false if the sequence is a replay or too old.
func (w *Window) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq > w.maxSeq {
		shift := seq - w.maxSeq
		if shift >= 64 {
			w.seen = 1 // only current bit
		} else {
			w.seen = (w.seen << shift) | 1
		}
		w.maxSeq = seq
		return true
	}

	// seq <= maxSeq
	offset := w.maxSeq - seq
	if offset >= w.window {
		return false
	}
	mask := uint64(1) << offset
	if w.seen&mask != 0 {
		return false
	}
	w.seen |= mask
	return true
}
