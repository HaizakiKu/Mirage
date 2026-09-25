package core

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/traffic"
	"github.com/quic-go/quic-go"
)

// Client listens for SOCKS5 connections locally and proxies them through
// a Mirage server via QUIC
type Client struct {
	cfg    *config.ClientConfig
	shaper *traffic.TrafficShaper

	mu    sync.Mutex
	conn  *quic.Conn
	demux *udpDemux

	rootCAs          *x509.CertPool // tests only: trust a self-signed server cert
	handshakeTimeout time.Duration  // tests only: override HandshakeIdleTimeout
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
	log.Printf("mirage client SOCKS5 listening on %s", listen)
	return c.serve(ctx, ln)
}

// serve accepts SOCKS5 connections on ln until ctx is done. Called by Run and by tests
func (c *Client) serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

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

	host, port, cmd, err := socks5Handshake(rawConn)
	if err != nil {
		log.Printf("SOCKS5 handshake: %v", err)
		return
	}

	switch cmd {
	case socks5CmdConnect:
		c.handleConnect(ctx, rawConn, host, port)
	case socks5CmdUDP:
		c.handleUDPAssociate(ctx, rawConn)
	default:
		socks5SendReply(rawConn, socks5RepCmdNotSupported, nil)
	}
}

// handleConnect proxies a SOCKS5 CONNECT request over a new QUIC stream.
func (c *Client) handleConnect(ctx context.Context, rawConn net.Conn, host string, port uint16) {
	stream, _, err := c.openStream(ctx)
	if err != nil {
		log.Printf("CONNECT %s: %v", net.JoinHostPort(host, fmt.Sprint(port)), err)
		socks5SendReply(rawConn, socks5RepConnRefused, nil)
		return
	}

	command := CmdTCP
	if c.shaper.Enabled() {
		command |= CmdFlagPadded
	}
	if err := c.writeHeader(stream, command, host, port); err != nil {
		log.Printf("send auth header: %v", err)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		socks5SendReply(rawConn, socks5RepGeneralFailure, nil)
		return
	}

	// Only the payload after the header is shaped (and padding-framed).
	shaped := c.shaper.WrapStream(stream)

	socks5SendReply(rawConn, socks5RepSuccess, nil)
	relay(ctx, stream, stream, shaped, rawConn)
}

// writeHeader sends the auth header, unshaped, as the first bytes of stream.
func (c *Client) writeHeader(stream *quic.Stream, command Command, host string, port uint16) error {
	addrType, addr := addrTypeFor(host)
	hdr := &AuthHeader{
		Version:  Version,
		Token:    MakeToken(c.cfg.Password),
		Command:  command,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	}
	_, err := stream.Write(hdr.Encode())
	return err
}

// handleUDPAssociate implements SOCKS5 UDP ASSOCIATE. Packets from the
// application are relayed as QUIC datagrams tagged with the session ID (the
// control stream's ID); the association ends when the SOCKS TCP connection closes.
func (c *Client) handleUDPAssociate(ctx context.Context, rawConn net.Conn) {
	tcpClient, _ := rawConn.RemoteAddr().(*net.TCPAddr)
	localTCP, _ := rawConn.LocalAddr().(*net.TCPAddr)
	var bindIP net.IP
	if localTCP != nil {
		bindIP = localTCP.IP
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		log.Printf("UDP associate listen: %v", err)
		socks5SendReply(rawConn, socks5RepGeneralFailure, nil)
		return
	}
	defer pc.Close()

	stream, demux, err := c.openStream(ctx)
	if err != nil {
		log.Printf("UDP associate: %v", err)
		socks5SendReply(rawConn, socks5RepGeneralFailure, nil)
		return
	}
	defer func() {
		stream.CancelRead(0)
		stream.Close()
	}()

	id := uint32(stream.StreamID())
	in := demux.register(id)
	defer demux.unregister(id)

	if err := c.writeHeader(stream, CmdUDP, "0.0.0.0", 0); err != nil {
		log.Printf("send auth header: %v", err)
		socks5SendReply(rawConn, socks5RepGeneralFailure, nil)
		return
	}
	// Wait for the server to register the session.
	var ack [1]byte
	stream.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(stream, ack[:]); err != nil {
		log.Printf("UDP associate: no server ack: %v", err)
		socks5SendReply(rawConn, socks5RepGeneralFailure, nil)
		return
	}
	stream.SetReadDeadline(time.Time{}) //nolint:errcheck

	socks5SendReply(rawConn, socks5RepSuccess, pc.LocalAddr().(*net.UDPAddr))

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(demux.conn.Context(), cancel)
	defer stop()
	go func() {
		// Server closed the control stream or the TCP side went away.
		io.Copy(io.Discard, stream) //nolint:errcheck
		cancel()
	}()
	go func() {
		<-sctx.Done()
		rawConn.Close()
		pc.Close()
	}()

	var appAddr atomic.Pointer[net.UDPAddr]

	// application → server
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				cancel()
				return
			}
			if tcpClient != nil && !from.IP.Equal(tcpClient.IP) {
				continue // only the client that made the association may use it
			}
			// SOCKS5 UDP request header: RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA
			if n < 4 || buf[2] != 0 {
				continue // fragmentation is not supported
			}
			r := &sliceReader{b: buf[3:n]}
			t, addr, port, err := readAddr(r) // SOCKS5 ATYP values match AddrType
			if err != nil {
				continue
			}
			appAddr.Store(from)
			demux.conn.SendDatagram(EncodeUDPDatagram(id, t, addr, port, r.b)) //nolint:errcheck
		}
	}()

	// server → application
	go func() {
		for {
			select {
			case <-sctx.Done():
				return
			case data := <-in:
				d, err := DecodeUDPDatagram(data)
				if err != nil {
					continue
				}
				to := appAddr.Load()
				if to == nil {
					continue
				}
				pkt := appendAddr([]byte{0, 0, 0}, d.AddrType, d.Addr, d.Port)
				pc.WriteToUDP(append(pkt, d.Payload...), to) //nolint:errcheck
			}
		}
	}()

	// RFC 1928: the association terminates when the TCP connection closes.
	io.Copy(io.Discard, rawConn) //nolint:errcheck
	cancel()
}

// openStream opens a new QUIC stream, reconnecting if needed
func (c *Client) openStream(ctx context.Context) (*quic.Stream, *udpDemux, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || isConnClosed(c.conn) {
		if err := c.redial(ctx); err != nil {
			return nil, nil, err
		}
	}

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		if err := c.redial(ctx); err != nil {
			return nil, nil, fmt.Errorf("reconnect: %w", err)
		}
		stream, err = c.conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	return stream, c.demux, nil
}

// redial replaces the current connection. Must be called with c.mu held.
func (c *Client) redial(ctx context.Context) error {
	if c.conn != nil {
		c.conn.CloseWithError(0, "") //nolint:errcheck
		c.conn, c.demux = nil, nil
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	c.conn = conn
	c.demux = newUDPDemux(conn)
	return nil
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
	if c.rootCAs != nil {
		tlsCfg.RootCAs = c.rootCAs
	}
	qcfg := quicClientConfig
	if c.handshakeTimeout > 0 {
		qcfg = quicClientConfig.Clone()
		qcfg.HandshakeIdleTimeout = c.handshakeTimeout
	}
	conn, err := quic.DialAddr(ctx, server, tlsCfg, qcfg)
	if err != nil {
		return nil, dialError(server, err)
	}
	return conn, nil
}

// dialError wraps a connection failure with the server address and, when no
// reply ever arrived, a hint about the most common cause.
func dialError(server string, err error) error {
	var idle *quic.IdleTimeoutError
	var hs *quic.HandshakeTimeoutError
	if errors.As(err, &idle) || errors.As(err, &hs) {
		_, port, _ := net.SplitHostPort(server)
		return fmt.Errorf("connect to server %s: %w (no reply from server over UDP: check the server is running and UDP port %s is open in its firewall / cloud security group)", server, err, port)
	}
	var te *quic.TransportError
	if errors.As(err, &te) && te.Remote && te.ErrorCode.IsCryptoError() {
		return fmt.Errorf("connect to server %s: %w (the server rejected the TLS handshake: check the server log, e.g. its certificate is not available)", server, err)
	}
	return fmt.Errorf("connect to server %s: %w", server, err)
}

func isConnClosed(conn *quic.Conn) bool {
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

// udpDemux dispatches the QUIC datagrams of one client connection to the
// UDP associations (keyed by session ID) that share it.
type udpDemux struct {
	conn *quic.Conn
	once sync.Once

	mu       sync.Mutex
	sessions map[uint32]chan []byte
}

func newUDPDemux(conn *quic.Conn) *udpDemux {
	return &udpDemux{conn: conn, sessions: make(map[uint32]chan []byte)}
}

func (d *udpDemux) register(id uint32) <-chan []byte {
	ch := make(chan []byte, 128)
	d.mu.Lock()
	d.sessions[id] = ch
	d.mu.Unlock()
	d.once.Do(func() { go d.loop() })
	return ch
}

func (d *udpDemux) unregister(id uint32) {
	d.mu.Lock()
	delete(d.sessions, id)
	d.mu.Unlock()
}

func (d *udpDemux) loop() {
	for {
		data, err := d.conn.ReceiveDatagram(d.conn.Context())
		if err != nil {
			return
		}
		if len(data) < 4 {
			continue
		}
		id := binary.BigEndian.Uint32(data)
		d.mu.Lock()
		ch := d.sessions[id]
		d.mu.Unlock()
		if ch == nil {
			continue
		}
		select {
		case ch <- data:
		default: // backlogged: drop, as UDP would
		}
	}
}

//Minimal SOCKS5 implementation

const (
	socks5Version    = 0x05
	socks5NoAuth     = 0x00
	socks5NoAccepted = 0xFF

	socks5CmdConnect = 0x01
	socks5CmdUDP     = 0x03

	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04

	socks5RepSuccess         = 0x00
	socks5RepGeneralFailure  = 0x01
	socks5RepConnRefused     = 0x05
	socks5RepCmdNotSupported = 0x07
)

// socks5Handshake performs method negotiation and reads the request.
func socks5Handshake(conn net.Conn) (host string, port uint16, cmd byte, err error) {
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		return "", 0, 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	methods := make([]byte, header[1])
	if _, err = io.ReadFull(conn, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{socks5NoAuth}) {
		conn.Write([]byte{socks5Version, socks5NoAccepted}) //nolint:errcheck
		return "", 0, 0, fmt.Errorf("client offers no supported auth method")
	}
	conn.Write([]byte{socks5Version, socks5NoAuth}) //nolint:errcheck

	req := make([]byte, 4)
	if _, err = io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != socks5Version {
		return "", 0, 0, fmt.Errorf("unsupported SOCKS version: %d", req[0])
	}
	cmd = req[1]

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
		socks5SendReply(conn, 0x08, nil) // address type not supported
		return "", 0, 0, fmt.Errorf("unsupported address type: 0x%02x", req[3])
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)
	return
}

// socks5SendReply writes a SOCKS5 reply; bind may be nil (reported as 0.0.0.0:0).
func socks5SendReply(conn net.Conn, rep byte, bind *net.UDPAddr) {
	reply := []byte{socks5Version, rep, 0x00}
	if bind == nil {
		reply = append(reply, socks5AddrIPv4, 0, 0, 0, 0, 0, 0)
	} else {
		t, host := addrTypeFor(bind.IP.String())
		reply = appendAddr(reply, t, host, uint16(bind.Port))
	}
	conn.Write(reply) //nolint:errcheck
}
