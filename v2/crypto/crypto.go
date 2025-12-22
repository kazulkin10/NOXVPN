package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const keyLen = 32

// DeriveSessionKeys derives tx/rx keys using HKDF over the master key and nonces.
func DeriveSessionKeys(master []byte, sessionID [8]byte, clientNonce, serverNonce []byte, isServer bool) (txKey, rxKey []byte, err error) {
	if len(master) != keyLen {
		return nil, nil, errors.New("master key must be 32 bytes")
	}
	salt := make([]byte, 8+len(clientNonce)+len(serverNonce))
	copy(salt, sessionID[:])
	copy(salt[8:], clientNonce)
	copy(salt[8+len(clientNonce):], serverNonce)

	infoTx := []byte("noxv2-tx")
	infoRx := []byte("noxv2-rx")
	if isServer {
		infoTx, infoRx = infoRx, infoTx
	}

	hkTx := hkdf.New(sha256.New, master, salt, infoTx)
	hkRx := hkdf.New(sha256.New, master, salt, infoRx)
	txKey = make([]byte, keyLen)
	rxKey = make([]byte, keyLen)
	if _, err = io.ReadFull(hkTx, txKey); err != nil {
		return nil, nil, err
	}
	if _, err = io.ReadFull(hkRx, rxKey); err != nil {
		return nil, nil, err
	}
	return txKey, rxKey, nil
}

// CipherState wraps AEAD with a monotonically increasing nonce/seq.
type CipherState struct {
	aead  cipher
	seq   uint64
	epoch uint32
}

type cipher interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewCipherState constructs CipherState from a key and epoch.
func NewCipherState(key []byte, epoch uint32) (*CipherState, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &CipherState{aead: a, epoch: epoch}, nil
}

// Seq returns the next sequence value that will be used for sealing.
func (c *CipherState) Seq() uint64 {
	return c.seq
}

// NextNonce builds a 12-byte nonce with epoch|seq.
func (c *CipherState) NextNonce() []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[0:4], c.epoch)
	binary.BigEndian.PutUint64(nonce[4:12], c.seq)
	return nonce
}

// Seal increments seq and seals plaintext.
func (c *CipherState) Seal(ad, plaintext []byte) []byte {
	nonce := c.NextNonce()
	ct := c.aead.Seal(nil, nonce, plaintext, ad)
	c.seq++
	return ct
}

// Open decrypts ciphertext with provided seq (for replay-guard).
func (c *CipherState) Open(seq uint64, ad, ciphertext []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[0:4], c.epoch)
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return c.aead.Open(nil, nonce, ciphertext, ad)
}

// RandomBytes returns n random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
