package socks

import (
	"context"
	"errors"
	"net"
	"github.com/koomox/wireproxy/tunnel"
)

type Conn struct {
	net.Conn
	metadata *tunnel.Metadata
	hash     []byte
	payload  []byte
}

func (c *Conn) Hash() string {
	return string(c.hash)
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *Conn) Payload() []byte {
	return c.payload
}

type packetInfo struct {
	metadata *tunnel.Metadata
	payload  []byte
}

type PacketConn struct {
	net.PacketConn
	in     chan *packetInfo
	out    chan *packetInfo
	src    net.Addr
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *PacketConn) Close() error {
	c.cancel()
	return nil
}

func (c *PacketConn) WriteWithMetadata(payload []byte, m *tunnel.Metadata) (int, error) {
	select {
	case c.out <- &packetInfo{metadata: m, payload: payload}:
		return len(payload), nil
	case <-c.ctx.Done():
		return 0, errors.New("socks packet conn closed")
	}
}

func (c *PacketConn) ReadWithMetadata(payload []byte) (int, *tunnel.Metadata, error) {
	select {
	case info := <-c.in:
		n := copy(payload, info.payload)
		return n, info.metadata, nil
	case <-c.ctx.Done():
		return 0, nil, errors.New("socks packet conn closed")
	}
}
