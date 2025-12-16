package mux

import "sync"

type Session struct {
    ID       string
    Streams  map[uint32]*Stream
    BytesIn  uint64
    BytesOut uint64

    mu sync.Mutex
}

func NewSession(id string) *Session {
    return &Session{
        ID:      id,
        Streams: make(map[uint32]*Stream),
    }
}

func (s *Session) AddStream(stream *Stream) {
    s.mu.Lock()
    s.Streams[stream.ID] = stream
    s.mu.Unlock()
}

func (s *Session) RemoveStream(id uint32) {
    s.mu.Lock()
    delete(s.Streams, id)
    s.mu.Unlock()
}

func (s *Session) AddBytesIn(n uint64) {
    s.mu.Lock()
    s.BytesIn += n
    s.mu.Unlock()
}

func (s *Session) AddBytesOut(n uint64) {
    s.mu.Lock()
    s.BytesOut += n
    s.mu.Unlock()
}
