package crypto

import (
"crypto/cipher"
"crypto/rand"
"encoding/binary"
"errors"
"sync/atomic"

"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
aead  cipher.AEAD
nonce uint64
}

func NewCipherFromKey(key []byte) (*Cipher, error) {
if len(key) != chacha20poly1305.KeySize {
return nil, errors.New("bad key size")
}
a, err := chacha20poly1305.New(key)
if err != nil {
return nil, err
}
return &Cipher{aead: a}, nil
}

func NewRandomKey() ([]byte, error) {
k := make([]byte, chacha20poly1305.KeySize)
_, err := rand.Read(k)
return k, err
}

func (c *Cipher) Seal(plain []byte) []byte {
n := atomic.AddUint64(&c.nonce, 1)
nonce := make([]byte, chacha20poly1305.NonceSize)
binary.BigEndian.PutUint64(nonce[4:], n) // 12 bytes: 4 zeros + counter
out := c.aead.Seal(nil, nonce, plain, nil)
return append(nonce, out...)
}

func (c *Cipher) Open(msg []byte) ([]byte, error) {
if len(msg) < chacha20poly1305.NonceSize {
return nil, errors.New("short msg")
}
nonce := msg[:chacha20poly1305.NonceSize]
ct := msg[chacha20poly1305.NonceSize:]
return c.aead.Open(nil, nonce, ct, nil)
}
