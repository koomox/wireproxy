package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/koomox/wireproxy/logger"
	"github.com/koomox/wireproxy/socks"
	"github.com/koomox/wireproxy/tunnel"
	"github.com/koomox/wireproxy/wire"
)

const version = "1.0.0"

var (
	cmdQ = make(chan string)
)

func main() {
	if wire.GetVersion(os.Args...) {
		fmt.Printf("wireproxy version: %s\n", version)
		return
	}
	dev, err := wire.FromFile(wire.FromArgs(os.Args...))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if dev.Socks5Addr() == "" {
		fmt.Println("not found Socks5 BindAddress")
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	go func(ch chan string) {
		for {
			select {
			case sig := <-sigChan:
				switch sig {
				case os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
					ch <- "exit"
				default:
				}
			}
		}
	}(cmdQ)

	fmt.Println("loading...")
	fmt.Println(dev.IPCRequest())
	for i := range dev.Endpoint {
		fmt.Println(dev.Endpoint[i].String())
	}
	tun, err := dev.Up(wire.LogLevelVerbose)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	server, err := socks.NewServer(dev.Socks5Addr(), context.Background(), logger.Std)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	go func(ctx context.Context, vt *wire.VirtualTun, source *socks.Server) {
		for {
			inbound, err := source.AcceptConn()
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			go func(inbound tunnel.Conn) {
				defer inbound.Close()
				fmt.Println(inbound.Metadata().String())
				outbound, err := vt.Tnet.DialContext(ctx, "tcp", inbound.Metadata().String())
				if err != nil {
					fmt.Printf("proxy failed to dial connection\n")
					return
				}
				defer outbound.Close()
				errChan := make(chan error, 2)
				copyConn := func(a, b net.Conn) {
					_, err := io.Copy(a, b)
					errChan <- err
				}
				go copyConn(inbound, outbound)
				go copyConn(outbound, inbound)
				select {
				case err = <-errChan:
					if err != nil {
						fmt.Println(err.Error())
						return
					}
				case <-ctx.Done():
					fmt.Printf("shutting down conn relay\n")
					return
				}
			}(inbound)
		}
	}(context.Background(), tun, server)

	for {
		select {
		case msg := <-cmdQ:
			switch msg {
			case "quit", "exit":
				os.Exit(0)
			default:
			}
		}
	}
}
