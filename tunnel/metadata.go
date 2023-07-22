package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	IPv4       byte = 0x01
	DomainName byte = 0x03
	IPv6       byte = 0x04
)

type Address struct {
	DomainName  string
	Port        int
	NetworkType string
	AddressType byte
	net.IP
}

type Metadata struct {
	Command byte
	*Address
}

func (r *Metadata) ReadFrom(reader io.Reader) (err error) {
	b := [1]byte{}
	if _, err = io.ReadFull(reader, b[:]); err != nil {
		return err
	}
	r.Command = b[0]
	r.Address = &Address{}
	if err = r.Address.ReadFrom(reader); err != nil {
		return fmt.Errorf("failed to read address %v", err.Error())
	}
	return
}

func (r *Metadata) WriteTo(w io.Writer) (err error) {
	buf := bytes.NewBuffer(make([]byte, 0, 64))
	buf.WriteByte(r.Command)
	if err = r.Address.WriteTo(buf); err != nil {
		return
	}
	r.Address.NetworkType = "tcp"
	_, err = w.Write(buf.Bytes())
	return
}

func (r *Metadata) AddrType() byte {
	return r.AddressType
}

func (r *Metadata) Port() string {
	return fmt.Sprintf("%d", r.Address.Port)
}

func (r *Metadata) Host() string {
	return r.Address.Host()
}

func (r *Metadata) Network() string {
	return r.Address.Network()
}

func (r *Metadata) String() string {
	return r.Address.String()
}

func (a *Address) Host() string {
	switch a.AddressType {
	case IPv4, IPv6:
		return a.IP.String()
	case DomainName:
		return a.DomainName
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (a *Address) String() string {
	switch a.AddressType {
	case IPv4:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	case IPv6:
		return fmt.Sprintf("[%s]:%d", a.IP.String(), a.Port)
	case DomainName:
		return fmt.Sprintf("%s:%d", a.DomainName, a.Port)
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (r *Address) Network() string {
	return r.NetworkType
}

func (a *Address) ResolveIP() (net.IP, error) {
	if a.AddressType == IPv4 || a.AddressType == IPv6 {
		return a.IP, nil
	}
	if a.IP != nil {
		return a.IP, nil
	}
	addr, err := net.ResolveIPAddr("ip", a.DomainName)
	if err != nil {
		return nil, err
	}
	a.IP = addr.IP
	return addr.IP, nil
}

func (r *Address) ReadFrom(reader io.Reader) (err error) {
	b := make([]byte, 512)
	offset := 1
	if _, err = io.ReadFull(reader, b[:1]); err != nil {
		return fmt.Errorf("unable to read ATYP %v", err.Error())
	}
	r.AddressType = b[0]
	switch r.AddressType {
	case IPv4:
		offset += net.IPv4len
		if _, err = io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv4 %v", err.Error())
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case IPv6:
		offset += net.IPv6len
		if _, err = io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv6 %v", err.Error())
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case DomainName:
		offset += 1
		if _, err = io.ReadFull(reader, b[1:offset]); err != nil {
			return fmt.Errorf("failed to read domain name length")
		}
		offset += int(b[1])
		if _, err = io.ReadFull(reader, b[2:offset+2]); err != nil {
			return fmt.Errorf("failed to read domain name %v", err.Error())
		}
		r.DomainName = string(b[2:offset])
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		if ip := net.ParseIP(r.DomainName); ip != nil {
			r.IP = ip
			if ip.To4() != nil {
				r.AddressType = IPv4
			} else {
				r.AddressType = IPv6
			}
		}
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}
	return
}

func (r *Address) WriteTo(w io.Writer) (err error) {
	if _, err = w.Write([]byte{r.AddressType}); err != nil {
		return
	}
	switch r.AddressType {
	case DomainName:
		if _, err = w.Write([]byte{byte(len(r.DomainName))}); err != nil {
			return
		}
		if _, err = w.Write([]byte(r.DomainName)); err != nil {
			return
		}
	case IPv4:
		if _, err = w.Write(r.IP.To4()); err != nil {
			return
		}
	case IPv6:
		if _, err = w.Write(r.IP.To16()); err != nil {
			return
		}
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}
	port := [2]byte{}
	binary.BigEndian.PutUint16(port[:], uint16(r.Port))
	_, err = w.Write(port[:])
	return
}

func (r *Address) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 64))
	r.WriteTo(buf)
	return buf.Bytes()
}

func ResolveAddr(network, address string) (*Address, error) {
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed")
	}
	port, err := strconv.ParseInt(p, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed to port %v", p)
	}
	r := &Address{NetworkType: network, Port: int(port)}
	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			r.AddressType = IPv4
			r.IP = ip4
		} else {
			r.AddressType = IPv6
			r.IP = ip
		}
	} else {
		hostLen := len(host)
		if hostLen > 255 {
			return nil, fmt.Errorf("resolve addr failed to host length size %v", hostLen)
		}
		r.AddressType = DomainName
		r.DomainName = host
	}

	return r, nil
}

func SplitAddr(b []byte) (*Address, error) {
	offset := 1 + net.IPv4len + 2
	if len(b) < offset {
		return nil, fmt.Errorf("split addr is short")
	}
	r := &Address{AddressType: b[0]}
	switch r.AddressType {
	case DomainName:
		offset = 1 + 1 + int(b[1])
		if len(b) < offset+2 {
			return nil, fmt.Errorf("split addr is short")
		}
		r.DomainName = string(b[2:offset])
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		if ip := net.ParseIP(r.DomainName); ip != nil {
			r.IP = ip
			if ip.To4() != nil {
				r.AddressType = IPv4
			} else {
				r.AddressType = IPv6
			}
		}
	case IPv4:
		offset = 1 + net.IPv4len
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case IPv6:
		offset = 1 + net.IPv6len
		if len(b) < offset+2 {
			return nil, fmt.Errorf("split addr is short")
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	default:
		return nil, fmt.Errorf("split addr is unknow")
	}

	return r, nil
}
