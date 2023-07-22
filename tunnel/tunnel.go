package tunnel

import (
	"net"
)

type Conn interface {
	net.Conn
	Hash() string
	Metadata() *Metadata
}

type PacketConn interface {
	net.PacketConn
	WriteWithMetadata([]byte, *Metadata) (int, error)
	ReadWithMetadata([]byte) (int, *Metadata, error)
}