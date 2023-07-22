package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/koomox/wireguard-go/conn"
	"github.com/koomox/wireguard-go/device"
	"github.com/koomox/wireguard-go/tun/netstack"
)

const (
	LogLevelSilent = iota
	LogLevelError
	LogLevelVerbose
)

type PeerConfig struct {
	PublicKey    string         `json:"PublicKey"`
	PreSharedKey string         `json:"PreSharedKey"`
	Endpoint     string         `json:"Endpoint "`
	KeepAlive    int            `json:"PersistentKeepalive"`
	AllowedIPs   []netip.Prefix `json:"AllowedIPs"`
}

type DeviceConfig struct {
	SecretKey  string        `json:"PrivateKey"`
	Endpoint   []netip.Addr  `json:"Address"`
	Peers      []*PeerConfig `json:"Peers"`
	DNS        []netip.Addr  `json:"DNS"`
	MTU        int           `json:"MTU"`
	ListenPort int           `json:"ListenPort"`
}

type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr []netip.Addr
	mtu        int
}

type VirtualTun struct {
	Tnet *netstack.Net
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid base64 string: %v", key)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("key should be 32 bytes: %v", key)
	}
	return hex.EncodeToString(decoded), nil
}

func parseNetIP(address string) ([]netip.Addr, error) {
	if address == "" {
		return []netip.Addr{}, nil
	}
	addrs := strings.Split(address, ",")

	var ips []netip.Addr
	for _, str := range addrs {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseCIDRNetIP(address string) ([]netip.Addr, error) {
	if address == "" {
		return []netip.Addr{}, nil
	}

	ipcidrs := strings.Split(address, ",")

	var ips []netip.Addr
	for _, str := range ipcidrs {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		addr := prefix.Addr()
		if prefix.Bits() != addr.BitLen() {
			return nil, fmt.Errorf("interface address subnet should be /32 for IPv4 and /128 for IPv6")
		}

		ips = append(ips, addr)
	}
	return ips, nil
}

func parseAllowedIPs(address string) ([]netip.Prefix, error) {
	if address == "" {
		return []netip.Prefix{}, nil
	}

	ipcidrs := strings.Split(address, ",")

	var ips []netip.Prefix
	for _, str := range ipcidrs {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func parseInt(s string) (int, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func resolveIPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func parseBytesToMetadata(key string, b []byte) (values map[string][]string, err error) {
	values = make(map[string][]string)
	if b == nil {
		return values, nil
	}
	lines := bytes.Split(b, []byte{'\n'})
	for _, line := range lines {
		p := string(line)
		p = strings.Replace(p, "\r", "", -1)
		p = strings.Replace(p, "\n", "", -1)
		p = Trim(p)
		if p == "" || strings.HasPrefix(p, "--") || strings.HasPrefix(p, "#") {
			continue
		}
		if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
			key = p
			continue
		}
		values[key] = append(values[key], p)
	}
	return values, nil
}

func parseFileToMetadata(key, file string) (map[string][]string, error) {
	b, err := os.ReadFile(file)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return parseBytesToMetadata(key, b)
}

func ParseInterface(metadata ...string) (device *DeviceConfig, err error) {
	device = &DeviceConfig{MTU: 1280}
	for i := range metadata {
		k, v := ParsePair(metadata[i])
		switch k {
		case "Address":
			device.Endpoint, err = parseCIDRNetIP(v)
			if err != nil {
				return device, err
			}
		case "PrivateKey":
			device.SecretKey, err = encodeBase64ToHex(v)
			if err != nil {
				return device, err
			}
		case "DNS":
			device.DNS, err = parseNetIP(v)
			if err != nil {
				return device, err
			}
		case "MTU":
			device.MTU, err = parseInt(v)
			if err != nil {
				return device, err
			}
		}
	}
	return device, nil
}

func ParsePeers(metadata ...string) (peer *PeerConfig, err error) {
	peer = &PeerConfig{}
	for i := range metadata {
		k, v := ParsePair(metadata[i])
		switch k {
		case "PublicKey":
			peer.PublicKey, err = encodeBase64ToHex(v)
			if err != nil {
				return peer, err
			}
		case "Endpoint":
			peer.Endpoint, err = resolveIPAndPort(v)
			if err != nil {
				return peer, err
			}
		case "AllowedIPs":
			peer.AllowedIPs, err = parseAllowedIPs(v)
			if err != nil {
				return peer, err
			}
		}
	}
	return peer, nil
}

func ParseSocks(metadata ...string) (string, error) {
	for i := range metadata {
		k, v := ParsePair(metadata[i])
		switch k {
		case "BindAddress":
			if v == "" {
				return "", fmt.Errorf("not found BindAddress")
			}
			return v, nil
		}
	}
	return "", nil
}

func parseMetadata(metadata map[string][]string) (device *DeviceConfig, err error) {
	data, ok := metadata["[Interface]"]
	if !ok {
		return nil, fmt.Errorf("not found Interface")
	}
	device, err = ParseInterface(data...)
	if err != nil {
		return nil, err
	}
	data, ok = metadata["[Peer]"]
	if !ok {
		return nil, fmt.Errorf("not found Peer")
	}
	peer, err := ParsePeers(data...)
	if err != nil {
		return nil, err
	}
	device.Peers = append(device.Peers, peer)
	return device, nil
}

func FromFile(file string) (*DeviceConfig, error) {
	metadata, err := parseFileToMetadata("normal", file)
	if err != nil {
		return nil, err
	}
	return parseMetadata(metadata)
}

func FromBytes(b []byte) (*DeviceConfig, error) {
	metadata, err := parseBytesToMetadata("normal", b)
	if err != nil {
		return nil, err
	}
	return parseMetadata(metadata)
}

func (d *DeviceConfig) IPCRequest() string {
	var request bytes.Buffer
	request.WriteString(fmt.Sprintf("private_key=%s\n", d.SecretKey))
	if d.Peers != nil {
		for _, peer := range d.Peers {
			request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
			request.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
			if len(peer.AllowedIPs) > 0 {
				for _, ip := range peer.AllowedIPs {
					request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
				}
			} else {
				request.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::0/0\n")
			}
		}
	}

	return request.String()
}

func (d *DeviceConfig) DeviceAddr() []netip.Addr {
	exp := regexp.MustCompile(`((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)`)
	for i := range d.Endpoint {
		if exp.FindString(d.Endpoint[i].String()) != "" {
			return []netip.Addr{d.Endpoint[i]}
		}
	}
	return nil
}

func (d *DeviceConfig) Up(level int) (*VirtualTun, error) {
	tun, tnet, err := netstack.CreateNetTUN(d.DeviceAddr(), d.DNS, d.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(level, ""))
	if err = dev.IpcSet(d.IPCRequest()); err != nil {
		return nil, err
	}
	if err = dev.Up(); err != nil {
		return nil, err
	}
	return &VirtualTun{Tnet: tnet}, nil
}
