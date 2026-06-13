package core

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/traffic"
	"github.com/quic-go/quic-go"
)

// Client listens for SOCKS5 connections locally and proxies them through
// a Mirage server via QUIC
type Client struct {
	cfg    *config.ClientConfig
	shaper *traffic.TrafficShaper

	mu   sync.Mutex
	conn *quic.Conn
}

// NewClient creates a Client. QUIC connection is established lazily
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	shaperEnabled := cfg.Traffic.Profile != ""
	shaper := traffic.New(traffic.Config{
		Profile: cfg.Traffic.Profile,
		Enabled: shaperEnabled,
	})
	return &Client{
		cfg:    cfg,
		shaper: shaper,
	}, nil
}

// Run starts the SOCKS5 listener and blocks until ctx is done
func (c *Client) Run(ctx context.Context) error {
	listen := c.cfg.SOCKS5Listen
	if listen == "" {
		listen = "127.0.0.1:1080"
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen %s: %w", listen, err)
	}
	defer ln.Close()

	log.Printf("mirage client SOCKS5 listening on %s", listen)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("accept SOCKS5: %v", err)
				continue
			}
		}
		go c.handleSOCKS5(ctx, conn)
	}
}

// handleSOCKS5 handles one SOCKS5 connection from a local application
func (c *Client) handleSOCKS5(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()

	target, cmd, err := socks5Handshake(rawConn)
	if err != nil {
		log.Printf("SOCKS5 handshake: %v", err)
		return
	}

	stream, err := c.openStream(ctx)
	if err != nil {
		log.Printf("open QUIC stream: %v", err)
		socks5SendError(rawConn)
		return
	}
	defer stream.Close()

	// Wrap stream write path with traffic shaping
	shaped := c.shaper.WrapStream(stream)

	command := CmdTCP
	if cmd == socks5CmdUDP {
		command = CmdUDP
	}

	addrType, addr, port, err := parseSOCKS5Target(target)
	if err != nil {
		log.Printf("parse target: %v", err)
		return
	}

	hdr := &AuthHeader{
		Version:  Version,
		Token:    MakeToken(c.cfg.Password),
		Command:  command,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	}

	if _, err := shaped.Write(hdr.Encode()); err != nil {
		log.Printf("send auth header: %v", err)
		return
	}

	socks5SendSuccess(rawConn, target)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(shaped, rawConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(rawConn, shaped)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// openStream opens a new QUIC stream, reconnecting if needed
func (c *Client) openStream(ctx context.Context) (*quic.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || isConnClosed(c.conn) {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, err
		}
		c.conn = conn
	}

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		conn, dialErr := c.dial(ctx)
		if dialErr != nil {
			return nil, fmt.Errorf("reconnect: %w", dialErr)
		}
		c.conn = conn
		return c.conn.OpenStreamSync(ctx)
	}
	return stream, nil
}

func (c *Client) dial(ctx context.Context) (*quic.Conn, error) {
	echBytes, err := ParseECHConfigList(c.cfg.ECHConfig)
	if err != nil {
		log.Printf("warning: failed to parse ECH config: %v", err)
	}

	server := c.cfg.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "443")
	}

	host, _, _ := net.SplitHostPort(server)

	if len(echBytes) == 0 {
		log.Printf("ECH config not found. Add DNS HTTPS record to your server domain for full protection. Running with uTLS fingerprint only.")
	}

	tlsCfg := ClientTLSConfig(host, echBytes)
	return NewQUICClient(ctx, server, tlsCfg)
}

func isConnClosed(conn *quic.Conn) bool {
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

//Minimal SOCKS5 implementation

const (
	socks5Version = 0x05
	socks5NoAuth  = 0x00
	socks5CmdTCP  = 0x01
	socks5CmdUDP  = 0x03

	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04
)

func socks5Handshake(conn net.Conn) (target string, cmd byte, err error) {
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	methods := make([]byte, header[1])
	if _, err = io.ReadFull(conn, methods); err != nil {
		return
	}
	conn.Write([]byte{socks5Version, socks5NoAuth}) //nolint:errcheck

	req := make([]byte, 4)
	if _, err = io.ReadFull(conn, req); err != nil {
		return
	}
	cmd = req[1]

	var host string
	switch req[3] {
	case socks5AddrIPv4:
		ip := make([]byte, 4)
		if _, err = io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case socks5AddrIPv6:
		ip := make([]byte, 16)
		if _, err = io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	default:
		return "", 0, fmt.Errorf("unsupported address type: 0x%02x", req[3])
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	target = fmt.Sprintf("%s:%d", host, port)
	return
}

func parseSOCKS5Target(target string) (AddrType, string, uint16, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return 0, "", 0, err
	}

	var port int
	fmt.Sscan(portStr, &port)

	ip := net.ParseIP(host)
	if ip == nil {
		return AddrHostname, host, uint16(port), nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return AddrIPv4, host, uint16(port), nil
	}
	return AddrIPv6, host, uint16(port), nil
}

func socks5SendSuccess(conn net.Conn, _ string) {
	reply := []byte{socks5Version, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply) //nolint:errcheck
}

func socks5SendError(conn net.Conn) {
	reply := []byte{socks5Version, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply) //nolint:errcheck
}
