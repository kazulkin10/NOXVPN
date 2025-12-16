package mux

import (
    "sync"
    "nox-core/pkg/frame"
    "nox-core/pkg/crypto"
)

type Stream struct {
    ID       uint32
    BytesIn  uint64
    BytesOut uint64
}

type StreamHandler func(*frame.Frame)

type Mux struct {
    mu       sync.Mutex
    handlers map[uint32]StreamHandler
    streams  map[uint32]*Stream
    session  *Session
    cipher   *crypto.Cipher
}

func NewMux() *Mux {
    return &Mux{
        handlers: make(map[uint32]StreamHandler),
        streams:  make(map[uint32]*Stream),
        session:  NewSession("default"),
    }
}

func (m *Mux) SetCipher(c *crypto.Cipher) {
    m.mu.Lock()
    m.cipher = c
    m.mu.Unlock()
}

func (m *Mux) RegisterStream(id uint32, h StreamHandler) {
    m.mu.Lock()
    m.handlers[id] = h
    m.mu.Unlock()
}

func (m *Mux) CloseStream(id uint32) {
    m.mu.Lock()
    delete(m.handlers, id)
    delete(m.streams, id)
    m.session.RemoveStream(id)
    m.mu.Unlock()
}

func (m *Mux) HandleFrame(f *frame.Frame, write func([]byte)) {
    m.mu.Lock()

    s, exists := m.streams[f.StreamID]
    if !exists {
        s = &Stream{ID: f.StreamID}
        m.streams[f.StreamID] = s
        m.session.AddStream(s)
    }

    s.BytesIn += uint64(len(f.Payload))
    m.session.AddBytesIn(uint64(len(f.Payload)))

    handler, has := m.handlers[f.StreamID]
    m.mu.Unlock()

    if has {
        handler(f)
        return
    }

    // default echo handler for new streams
    echo := func(fr *frame.Frame) {
        resp := &frame.Frame{
            Type:     fr.Type,
            Flags:    0,
            StreamID: fr.StreamID,
            Payload:  fr.Payload,
        }
        out, _ := frame.EncodeFrame(resp)
        write(out)

        m.mu.Lock()
        s.BytesOut += uint64(len(fr.Payload))
        m.session.AddBytesOut(uint64(len(fr.Payload)))
        m.mu.Unlock()
    }

    m.RegisterStream(f.StreamID, echo)
    echo(f)
}
