package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"nox-core/v2/crypto"
	"nox-core/v2/protocol"
	"nox-core/v2/replay"
	"nox-core/v2/transport"
	"nox-core/v2/tun"
)

// FSM (client): Init -> HelloSent -> AssignRecv -> Ready -> Rekeying? -> Closing.

type Options struct {
	Key     []byte
	Session [8]byte
	Server  string
	MTU     int
	Timeout time.Duration
	TunName string
}

type Client struct {
	opts      Options
	tun       *tun.Device
	cipherTx  *crypto.CipherState
	cipherRx  *crypto.CipherState
	replay    *replay.Window
	assigned  net.IP
	prefixLen uint8
}

func New(opts Options) (*Client, error) {
	if len(opts.Key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.TunName == "" {
		opts.TunName = "nox1"
	}
	return &Client{opts: opts, replay: replay.New(64)}, nil
}

func (c *Client) Run(dialer transport.TCPDialer) error {
	conn, err := dialer.Dial(c.opts.Server)
	if err != nil {
		return err
	}
	defer conn.Close()

	// HELLO
	var hello protocol.Hello
	hello.Capabilities = protocol.CapMTUNeg | protocol.CapReplayGuard
	hello.SessionID = c.opts.Session
	randBytes, _ := crypto.RandomBytes(16)
	copy(hello.ClientNonce[:], randBytes)
	hello.DesiredMTU = uint16(c.opts.MTU)
	payload := append([]byte{protocol.CtrlHello}, protocol.EncodeHello(hello)...)
	if err := protocol.WriteRecord(conn, protocol.Frame{Version: protocol.Version, Kind: protocol.KindControl, Payload: payload}); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(c.opts.Timeout))
	assignFrame, err := protocol.ReadRecord(conn)
	if err != nil {
		return err
	}
	if assignFrame.Kind != protocol.KindControl || len(assignFrame.Payload) == 0 || assignFrame.Payload[0] != protocol.CtrlAssignIP {
		return fmt.Errorf("unexpected control")
	}
	assign, err := protocol.DecodeAssign(assignFrame.Payload[1:])
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})

	txKey, rxKey, err := crypto.DeriveSessionKeys(c.opts.Key, hello.SessionID, hello.ClientNonce[:], assign.ServerNonce[:], false)
	if err != nil {
		return err
	}
	txCipher, _ := crypto.NewCipherState(txKey, 1)
	rxCipher, _ := crypto.NewCipherState(rxKey, 1)
	c.cipherTx, c.cipherRx = txCipher, rxCipher
	c.assigned = net.IP(assign.IPv4[:])
	c.prefixLen = assign.PrefixLen

	// configure TUN
	_, subnet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", c.assigned.String(), c.prefixLen))
	mgr := tun.NewManager()
	dev, err := mgr.Ensure(tun.Config{Name: c.opts.TunName, CIDR: subnet, MTU: int(assign.MTU)})
	if err != nil {
		return err
	}
	c.tun = dev

	go c.pumpTun(conn)
	buf := make([]byte, 65535)
	for {
		frame, err := protocol.ReadRecord(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if frame.Kind != protocol.KindData || len(frame.Payload) < 8 {
			continue
		}
		seq := binary.BigEndian.Uint64(frame.Payload[:8])
		if !c.replay.Check(seq) {
			continue
		}
		pt, err := c.cipherRx.Open(seq, nil, frame.Payload[8:])
		if err != nil {
			continue
		}
		_, _ = c.tun.Tun.WritePacket(pt)
	}
	_ = buf
	return nil
}

func (c *Client) pumpTun(conn net.Conn) {
	buf := make([]byte, 65535)
	for {
		n, err := c.tun.Tun.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt := append([]byte{}, buf[:n]...)
		seq := c.cipherTx.Seq()
		ct := c.cipherTx.Seal(nil, pkt)
		payload := make([]byte, 8+len(ct))
		binary.BigEndian.PutUint64(payload[0:8], seq)
		copy(payload[8:], ct)
		_ = protocol.WriteRecord(conn, protocol.Frame{Version: protocol.Version, Kind: protocol.KindData, Payload: payload})
	}
}
