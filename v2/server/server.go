package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"nox-core/v2/crypto"
	"nox-core/v2/ipam"
	"nox-core/v2/protocol"
	"nox-core/v2/replay"
	"nox-core/v2/transport"
	"nox-core/v2/tun"
)

// FSM (server): Init -> HelloRecv -> AssignSent -> Ready -> Rekeying? -> Closing.
// Data frames are accepted only in Ready/Rekeying.

type Options struct {
	Key              []byte
	Subnet           *net.IPNet
	MTU              int
	HandshakeTimeout time.Duration
}

type Server struct {
	opts     Options
	ipam     *ipam.Manager
	tun      *tun.Device
	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	conn     net.Conn
	lease    ipam.Lease
	cipherTx *crypto.CipherState
	cipherRx *crypto.CipherState
	replay   *replay.Window
	epoch    uint32
}

func New(opts Options) (*Server, error) {
	if len(opts.Key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 5 * time.Second
	}
	ipmgr, err := ipam.New(opts.Subnet, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	mgr := tun.NewManager()
	dev, err := mgr.Ensure(tun.Config{Name: "nox0", CIDR: opts.Subnet, MTU: opts.MTU})
	if err != nil {
		return nil, err
	}
	return &Server{opts: opts, ipam: ipmgr, tun: dev, sessions: make(map[string]*session)}, nil
}

func (s *Server) Serve(listener *transport.TCPListener) error {
	go s.pumpTun()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout)); err != nil {
		log.Printf("conn deadline: %v", err)
	}
	frame, err := protocol.ReadRecord(conn)
	if err != nil {
		return
	}
	if frame.Kind != protocol.KindControl || len(frame.Payload) == 0 || frame.Payload[0] != protocol.CtrlHello {
		return
	}
	hello, err := protocol.DecodeHello(frame.Payload[1:])
	if err != nil {
		s.sendError(conn, 0x0001, "bad hello")
		return
	}
	if frame.Version != protocol.Version {
		s.sendError(conn, 0x0002, "version mismatch")
		return
	}
	lease, err := s.ipam.Allocate(hello.SessionID)
	if err != nil {
		s.sendError(conn, 0x0003, "ipam: "+err.Error())
		return
	}
	mtu := s.opts.MTU
	if mtu == 0 {
		mtu = 1400
	}
	if hello.DesiredMTU != 0 && int(hello.DesiredMTU) < mtu {
		mtu = int(hello.DesiredMTU)
	}
	var assign protocol.AssignIP
	assign.SessionID = hello.SessionID
	copy(assign.IPv4[:], lease.IP.To4())
	ones, _ := s.opts.Subnet.Mask.Size()
	assign.PrefixLen = uint8(ones)
	assign.MTU = uint16(mtu)
	serverNonce, _ := crypto.RandomBytes(16)
	copy(assign.ServerNonce[:], serverNonce)

	// Respond HELLO -> ASSIGN
	payload := append([]byte{protocol.CtrlAssignIP}, protocol.EncodeAssign(assign)...)
	_ = conn.SetDeadline(time.Time{})
	if err := protocol.WriteRecord(conn, protocol.Frame{Version: protocol.Version, Kind: protocol.KindControl, Payload: payload}); err != nil {
		s.ipam.Release(hello.SessionID)
		return
	}

	txKey, rxKey, err := crypto.DeriveSessionKeys(s.opts.Key, hello.SessionID, hello.ClientNonce[:], assign.ServerNonce[:], true)
	if err != nil {
		s.ipam.Release(hello.SessionID)
		return
	}
	txCipher, _ := crypto.NewCipherState(txKey, 1)
	rxCipher, _ := crypto.NewCipherState(rxKey, 1)

	sess := &session{conn: conn, lease: lease, cipherTx: txCipher, cipherRx: rxCipher, replay: replay.New(64), epoch: 1}
	s.registerSession(sess)
	defer s.unregisterSession(sess)

	s.runSession(sess)
}

func (s *Server) runSession(sess *session) {
	for {
		frame, err := protocol.ReadRecord(sess.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read frame: %v", err)
			}
			return
		}
		if frame.Kind != protocol.KindData {
			continue
		}
		if len(frame.Payload) < 8 {
			continue
		}
		seq := binary.BigEndian.Uint64(frame.Payload[:8])
		if !sess.replay.Check(seq) {
			continue
		}
		pt, err := sess.cipherRx.Open(seq, nil, frame.Payload[8:])
		if err != nil {
			continue
		}
		_, _ = s.tun.Tun.WritePacket(pt)
	}
}

func (s *Server) pumpTun() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Tun.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt := append([]byte{}, buf[:n]...)
		dest := ipv4Dest(pkt)
		if dest == nil {
			continue
		}
		sess := s.sessionByIP(dest.String())
		if sess == nil {
			continue
		}
		seq := sess.cipherTx.Seq()
		ct := sess.cipherTx.Seal(nil, pkt)
		payload := make([]byte, 8+len(ct))
		binary.BigEndian.PutUint64(payload[0:8], seq)
		copy(payload[8:], ct)
		_ = protocol.WriteRecord(sess.conn, protocol.Frame{Version: protocol.Version, Kind: protocol.KindData, Payload: payload})
	}
}

func (s *Server) sendError(conn net.Conn, code uint16, reason string) {
	payload := append([]byte{protocol.CtrlError}, protocol.EncodeClose(protocol.Close{Code: code, Reason: reason})...)
	_ = protocol.WriteRecord(conn, protocol.Frame{Version: protocol.Version, Kind: protocol.KindControl, Payload: payload})
}

func ipv4Dest(pkt []byte) net.IP {
	if len(pkt) < 20 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

func (s *Server) registerSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.lease.IP.String()] = sess
}

func (s *Server) unregisterSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sess.lease.IP.String())
	s.ipam.Release(sess.lease.Session)
}

func (s *Server) sessionByIP(ip string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[ip]
}
