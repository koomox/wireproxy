package socks

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"github.com/koomox/wireproxy/tunnel"
)

var (
	httpStatusOK = []byte("HTTP/1.0 200 Connection Established\r\n\r\n")
)

// local socks server  connect
func HttpOnceAccept(first byte, conn net.Conn) (addr *tunnel.Address, payload []byte, err error) {
	var (
		host string
		port string
	)

	buf := make([]byte, 4096)
	buf[0] = first
	io.ReadAtLeast(conn, buf[1:], 1)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if nil != err {
		return
	}
	host, port, err = net.SplitHostPort(req.Host)
	if nil != err {
		host = req.Host
		port = req.URL.Port()
	}
	scheme := req.URL.Scheme
	if "" == port {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	if addr, err = tunnel.ResolveAddr("tcp", net.JoinHostPort(host, port)); err != nil {
		return
	}
	method := req.Method
	switch method {
	case http.MethodConnect:
		_, err = conn.Write(httpStatusOK)
	default:
		removeHeaders(req)
		payload, err = httputil.DumpRequest(req, true)
	}
	return
}

func removeHeaders(req *http.Request) {
	req.RequestURI = ""
	req.Header.Del("Accept-Encoding")
	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	//req.Header.Del("Referer")
	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	req.Header.Del("Connection")
}
