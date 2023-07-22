package socks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/koomox/wireproxy/tunnel"
)

const (
	Connect   byte = 0x01
	Associate byte = 0x03

	MaxPacketSize = 8 * 1024
)

type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
	Debug(...interface{})
}

type Server struct {
	sync.RWMutex
	tcpListener net.Listener
	udpListener net.PacketConn
	timeout     time.Duration
	connChan    chan tunnel.Conn
	packetChan  chan tunnel.PacketConn
	mapping     map[string]*PacketConn
	log         Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	s.tcpListener.Close()
	return s.udpListener.Close()
}

func NewServer(addr string, ctx context.Context, log Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(ctx)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create tcp listener %v", err.Error())
	}
	udpListener, err := net.ListenPacket("udp", addr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create udp listener %v", err.Error())
	}
	s := &Server{
		tcpListener: tcpListener,
		udpListener: udpListener,
		timeout:     time.Duration(60) * time.Second,
		connChan:    make(chan tunnel.Conn, 32),
		packetChan:  make(chan tunnel.PacketConn, 32),
		mapping:     make(map[string]*PacketConn),
		log:         log,
		ctx:         ctx,
		cancel:      cancel,
	}
	log.Info("listening start tcp/udp ", addr)
	go s.acceptConnLoop()
	go s.packetDispatchLoop()
	return s, nil
}

func (s *Server) acceptConnLoop() {
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				s.log.Debug("exiting")
				return
			default:
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					continue
				}
				s.log.Errorf("socks accept error %v", err.Error())
				return
			}
		}
		go func(conn net.Conn) {
			b := [1]byte{}
			if _, err = io.ReadFull(conn, b[:]); err != nil {
				s.log.Errorf("failed to read socks first char %v", err.Error())
				conn.Close()
				return
			}
			if b[0] == Version5 {
				s.log.Debug("socks5 connection")
				cmd, addr, err := s.handshake(conn)
				if err != nil {
					conn.Close()
					s.log.Errorf("socks failed to handshake with client %v", err.Error())
					return
				}
				switch cmd {
				case Connect:
					if err = s.connect(conn); err != nil {
						s.log.Errorf("socks failed to respond CONNECT %v", err.Error())
						conn.Close()
						return
					}
					s.connChan <- &Conn{Conn: conn, metadata: &tunnel.Metadata{Command: Connect, Address: addr}, payload: nil}
				case Associate:
					defer conn.Close()
					laddr, err := tunnel.ResolveAddr("udp", conn.LocalAddr().String())
					if err != nil {
						return
					}
					if err = s.associate(conn, laddr); err != nil {
						s.log.Errorf("socks failed to respond to associate request %v", err.Error())
						return
					}
					buf := [16]byte{}
					conn.Read(buf[:])
					s.log.Debug("socks udp session ends")
				default:
					s.log.Errorf("unknown socks command %d", cmd)
					conn.Close()
				}
			} else {
				s.log.Debug("http connection")
				addr, payload, err := HttpOnceAccept(b[0], conn)
				if err != nil {
					s.log.Errorf("failed to http connection %v", err.Error())
					conn.Close()
					return
				}
				s.connChan <- &Conn{Conn: conn, metadata: &tunnel.Metadata{Command: Connect, Address: addr}, payload: payload}
			}
		}(conn)
	}
}

func (s *Server) Dial(payload []byte, addr string) (conn net.Conn, err error) {
	if conn, err = net.Dial("tcp", addr); err != nil {
		return
	}
	if payload != nil && len(payload) > 0 {
		_, err = conn.Write(payload)
	}
	return
}

func (s *Server) AcceptConn() (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, errors.New("socks server closed")
	}
}

func (s *Server) AcceptPacket() (tunnel.PacketConn, error) {
	select {
	case conn := <-s.packetChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, errors.New("socks server closed")
	}
}

func (s *Server) handshake(rw io.ReadWriter) (cmd byte, addr *tunnel.Address, err error) {
	b := make([]byte, 256)
	if _, err = rw.Read(b[:1]); err != nil {
		return 0, nil, fmt.Errorf("failed to read NMETHODS %v", err.Error())
	}
	n := b[0]
	if _, err = io.ReadFull(rw, b[:n]); err != nil {
		return 0, nil, fmt.Errorf("socks failed to read methods %v", err.Error())
	}
	if _, err = rw.Write([]byte{0x05, 0x00}); err != nil {
		return 0, nil, fmt.Errorf("failed to respond auth %v", err.Error())
	}
	if _, err = rw.Read(b[:3]); err != nil {
		return 0, nil, fmt.Errorf("failed to read command %v", err.Error())
	}
	addr = &tunnel.Address{}
	if err = addr.ReadFrom(rw); err != nil {
		return 0, nil, err
	}
	return b[1], addr, nil
}

func (s *Server) connect(w io.Writer) (err error) {
	_, err = w.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func (s *Server) associate(w io.Writer, addr *tunnel.Address) (err error) {
	buf := bytes.NewBuffer([]byte{0x05, 0x00, 0x00})
	if err = addr.WriteTo(buf); err != nil {
		return
	}
	_, err = w.Write(buf.Bytes())
	return
}

func (s *Server) packetDispatchLoop() {
	for {
		b := make([]byte, MaxPacketSize)
		n, src, err := s.udpListener.ReadFrom(b)
		if err != nil {
			select {
			case <-s.ctx.Done():
				s.log.Debug("exiting")
				return
			default:
				if er, ok := err.(*net.OpError); ok && er.Timeout() {
					continue // ignore i/o timeout
				}
				s.log.Errorf("socks read udp packet error %v", err.Error())
				return
			}
		}
		s.log.Debug("socks recv udp packet from", src)
		if n < 10 {
			return
		}
		s.RLock()
		conn, found := s.mapping[src.String()]
		s.RUnlock()
		if !found {
			ctx, cancel := context.WithCancel(s.ctx)
			conn = &PacketConn{
				in:         make(chan *packetInfo, 16),
				out:        make(chan *packetInfo, 16),
				ctx:        ctx,
				cancel:     cancel,
				PacketConn: s.udpListener,
				src:        src,
			}
			go func(conn *PacketConn) {
				defer conn.Close()

				for {
					select {
					case info := <-conn.out:
						buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
						buf.Write([]byte{0, 0, 0})
						if err := info.metadata.Address.WriteTo(buf); err != nil {
							return
						}
						buf.Write(info.payload)
						if _, err := s.udpListener.WriteTo(buf.Bytes(), conn.src); err != nil {
							s.log.Error("socks failed to respond packet to", src)
							return
						}
						s.log.Debug("socks respond udp packet to", src, "addr", info.metadata)
					case <-time.After(time.Second * 5):
						s.log.Info("socks udp session timeout, closed")
						s.Lock()
						delete(s.mapping, src.String())
						s.Unlock()
						return
					case <-conn.ctx.Done():
						s.log.Info("socks udp session closed")
						return
					}
				}
			}(conn)

			s.Lock()
			s.mapping[src.String()] = conn
			s.Unlock()

			s.packetChan <- conn
			s.log.Info("socks new udp session from", src)
		}
		r := bytes.NewBuffer(b[3:n])
		addr := &tunnel.Address{}
		if err := addr.ReadFrom(r); err != nil {
			s.log.Errorf("socks failed to parse incoming packet %v", err.Error())
			continue
		}
		payload := make([]byte, MaxPacketSize)
		length, _ := r.Read(payload)
		select {
		case conn.in <- &packetInfo{metadata: &tunnel.Metadata{Address: addr}, payload: payload[:length]}:
		default:
			s.log.Info("socks udp queue full")
		}
	}
}
