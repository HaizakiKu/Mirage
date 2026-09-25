package core

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/masq"
	"github.com/HaizakiKu/mirage/traffic"
	"github.com/HaizakiKu/mirage/traffic/congestion"
	ech "github.com/HaizakiKu/quic-ech"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/acme/autocert"
)

// masqHandler is satisfied by *masq.Server and by test mocks
type masqHandler interface {
	ServeQUICConn(conn *quic.Conn) error
}

type Server struct {
	cfg         *config.ServerConfig
	cert        tls.Certificate
	getCert     func(*tls.ClientHelloInfo) (*tls.Certificate, error) // non-nil in ACME mode
	masqSrv     masqHandler
	echProv     *ech.Provider
	tokens      *tokenCache
	authTimeout time.Duration
}

// NewServer loads TLS cert (or sets up ACME), fetches masquerade content, and prepares ECH keys.
// ACME mode is used when cfg.ACME.Domain is set; manual cert mode when cfg.TLS.Cert/Key are set.
func NewServer(cfg *config.ServerConfig) (*Server, error) {
	echProv, err := ech.NewProvider(cfg.ECH.PublicName, cfg.ECH.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("init ECH provider: %w", err)
	}

	cache, err := masq.NewStaticCache(cfg.Masquerade.URL, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("masquerade: %w", err)
	}

	if cfg.ACME.Domain != "" {
		getCert, err := startACME(cfg.ACME)
		if err != nil {
			return nil, err
		}
		srv := newServerInternal(cfg, tls.Certificate{}, masq.NewServer(cache), echProv)
		srv.getCert = getCert
		return srv, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}
	return newServerInternal(cfg, cert, masq.NewServer(cache), echProv), nil
}

// startACME creates an autocert.Manager for the given domain and starts an HTTP-01
// challenge listener on :80. Returns the GetCertificate callback for tls.Config.
//
// The certificate is obtained in the background at startup rather than inside
// a client's handshake: autocert would otherwise block each handshake for up to
// minutes while issuance runs (or fails), which clients only see as
// "timeout: no recent network activity" and the server never logs.
func startACME(cfg config.ACMEConfig) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = "/etc/mirage/acme-cache"
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("acme cache dir: %w", err)
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Cache:      autocert.DirCache(cacheDir),
		Email:      cfg.Email,
	}

	log.Printf("ACME: managing certificate for %s (cache: %s)", cfg.Domain, cacheDir)

	// HTTP-01 challenge server — must listen on :80 for Let's Encrypt to reach it
	if ln, err := net.Listen("tcp", ":80"); err != nil {
		log.Printf("ACME WARNING: cannot listen on TCP :80 (%v). Let's Encrypt HTTP-01 validation "+
			"needs port 80 on this host: stop the service using it, or use tls.cert/tls.key instead of acme. "+
			"Only an already cached certificate can be used.", err)
	} else {
		go func() {
			srv := &http.Server{Handler: m.HTTPHandler(nil)}
			if err := srv.Serve(ln); err != nil {
				log.Printf("acme http-01 listener: %v", err)
			}
		}()
	}

	ac := newACMECert(cfg.Domain, m.GetCertificate)
	go ac.obtainLoop()
	return ac.GetCertificate, nil
}

// acmeCert gates handshakes on a certificate that has already been obtained.
type acmeCert struct {
	domain string
	get    func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	ready  atomic.Bool

	logMu   sync.Mutex
	lastLog time.Time
}

func newACMECert(domain string, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *acmeCert {
	return &acmeCert{domain: domain, get: get}
}

// obtainLoop fetches the certificate (from cache or Let's Encrypt), retrying
// with backoff until it succeeds. Renewals are then handled by autocert itself.
func (a *acmeCert) obtainLoop() {
	backoff := 2 * time.Minute
	for {
		// An empty ClientHello selects the same (RSA) key type that autocert
		// picks for TLS 1.3/QUIC clients, so later handshakes hit this cert.
		start := time.Now()
		if _, err := a.get(&tls.ClientHelloInfo{ServerName: a.domain}); err == nil {
			a.ready.Store(true)
			log.Printf("ACME: certificate for %s ready (%v)", a.domain, time.Since(start).Round(time.Millisecond))
			return
		} else {
			log.Printf("ACME ERROR: cannot obtain certificate for %s: %v — clients cannot connect until this succeeds; retrying in %v", a.domain, err, backoff)
		}
		time.Sleep(backoff)
		if backoff < time.Hour {
			backoff *= 2
		}
	}
}

// GetCertificate is the tls.Config callback. Before the certificate exists it
// fails the handshake immediately instead of blocking it on issuance.
func (a *acmeCert) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !a.ready.Load() {
		a.logf("ACME: rejecting handshake from %v: certificate for %s not obtained yet", remoteAddr(hello), a.domain)
		return nil, fmt.Errorf("acme: certificate for %s not ready", a.domain)
	}
	cert, err := a.get(hello)
	if err != nil {
		a.logf("TLS handshake from %v (SNI %q): certificate error: %v", remoteAddr(hello), hello.ServerName, err)
	}
	return cert, err
}

// logf logs at most once per 10s so a stream of failing handshakes can't flood the log.
func (a *acmeCert) logf(format string, args ...any) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if time.Since(a.lastLog) < 10*time.Second {
		return
	}
	a.lastLog = time.Now()
	log.Printf(format, args...)
}

func remoteAddr(hello *tls.ClientHelloInfo) any {
	if hello != nil && hello.Conn != nil {
		return hello.Conn.RemoteAddr()
	}
	return "client"
}

// newServerInternal constructs a Server with pre-built dependencies
// Used by NewServer and by integration tests (which bypass file I/O)
func newServerInternal(cfg *config.ServerConfig, cert tls.Certificate, mh masqHandler, echProv *ech.Provider) *Server {
	return &Server{
		cfg:     cfg,
		cert:    cert,
		masqSrv: mh,
		echProv: echProv,
		tokens:  newTokenCache(),
	}
}

func (s *Server) getAuthTimeout() time.Duration {
	if s.authTimeout > 0 {
		return s.authTimeout
	}
	return 5 * time.Second
}

// Run creates a listener and serves until ctx is done
func (s *Server) Run(ctx context.Context) error {
	var tlsCfg *tls.Config
	if s.getCert != nil {
		tlsCfg = ServerTLSConfigDynamic(s.getCert, s.echProv)
	} else {
		tlsCfg = ServerTLSConfig(s.cert, s.echProv)
	}
	ln, err := newQUICListener(s.cfg.Listen, tlsCfg, statelessResetKey(s.cfg.Password))
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	if list := s.echProv.ConfigList(); len(list) > 0 {
		log.Printf("ECH config for clients (ech_config): %s", base64.StdEncoding.EncodeToString(list))
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on an existing listener. Called by Run and by tests
func (s *Server) Serve(ctx context.Context, ln *quic.Listener) error {
	defer ln.Close()
	log.Printf("mirage server listening on %s", ln.Addr())

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// readAuthHeader decodes the header from st, bounded by the auth timeout so a
// peer that sends a partial header cannot stall the handler forever.
func (s *Server) readAuthHeader(st *quic.Stream) (*AuthHeader, error) {
	st.SetReadDeadline(time.Now().Add(s.getAuthTimeout())) //nolint:errcheck
	hdr, err := DecodeAuthHeader(st)
	st.SetReadDeadline(time.Time{}) //nolint:errcheck
	return hdr, err
}

func (s *Server) handleConn(ctx context.Context, conn *quic.Conn) {
	authCtx, cancel := context.WithTimeout(ctx, s.getAuthTimeout())
	defer cancel()

	stream, err := conn.AcceptStream(authCtx)
	if err != nil {
		// No stream within timeout — active probe or idle scanner
		log.Printf("connection from %s: no request within %v, serving masquerade", conn.RemoteAddr(), s.getAuthTimeout())
		if serveErr := s.masqSrv.ServeQUICConn(conn); serveErr != nil {
			log.Printf("masq serve (timeout): %v", serveErr)
		}
		return
	}

	hdr, err := s.readAuthHeader(stream)
	var reason string
	switch {
	case err != nil:
		reason = fmt.Sprintf("not a Mirage request (%v)", err)
	case !ValidateToken(hdr.Token, s.cfg.Password):
		reason = "invalid token (wrong password, or client/server clocks differ by more than 30s)"
	case !s.tokens.markUsed(hdr.Token): // replay protection: same token rejected twice
		reason = "replayed token"
	}
	if reason != "" {
		log.Printf("connection from %s: %s, serving masquerade", conn.RemoteAddr(), reason)
		if serveErr := s.masqSrv.ServeQUICConn(conn); serveErr != nil {
			log.Printf("masq serve (bad auth): %v", serveErr)
		}
		return
	}
	log.Printf("client %s authenticated", conn.RemoteAddr())

	// Authenticated — apply congestion controller
	if s.cfg.Congestion.Jitter > 0 {
		congestion.UseJitteredBBR(conn, congestion.JitterConfig{
			Fraction:  s.cfg.Congestion.Jitter,
			Smoothing: 0.3,
		})
	} else {
		congestion.UseBBR(conn)
	}

	s.handleProxy(ctx, conn, stream, hdr)
}

// handleProxy routes traffic for an authenticated connection.
// The QUIC connection is trusted after the first-stream auth; subsequent streams
// only need the time-window check (no nonce check — same connection, same client).
// Every stream, whatever the command of the first one, is dispatched by its own header.
func (s *Server) handleProxy(ctx context.Context, conn *quic.Conn, firstStream *quic.Stream, h *AuthHeader) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(conn.Context(), cancel)
	defer stop()

	udp := newUDPMux(conn)

	dispatch := func(st *quic.Stream, hdr *AuthHeader) {
		switch hdr.Cmd() {
		case CmdTCP:
			s.proxyTCP(ctx, st, hdr)
		case CmdUDP:
			udp.serveSession(ctx, st)
		default:
			log.Printf("unknown command 0x%02x from %s", hdr.Command, conn.RemoteAddr())
			st.CancelRead(0)
			st.CancelWrite(0)
		}
	}

	go dispatch(firstStream, h)
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(st *quic.Stream) {
			hdr, err := s.readAuthHeader(st)
			if err != nil || !ValidateToken(hdr.Token, s.cfg.Password) {
				st.CancelRead(0)
				st.CancelWrite(0)
				return
			}
			dispatch(st, hdr)
		}(stream)
	}
}

func (s *Server) proxyTCP(ctx context.Context, stream *quic.Stream, h *AuthHeader) {
	var src io.Reader = stream
	if h.Padded() {
		src = traffic.NewPaddedReader(stream)
	}

	target := h.TargetAddr()
	dial := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dial.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	defer conn.Close()

	relay(ctx, stream, src, stream, conn)
}

// relay copies data in both directions between a QUIC stream and a TCP conn,
// propagating half-closes, and returns once both directions are finished (or
// ctx is cancelled). src/dst are the stream's read and write sides, possibly
// wrapped (de-padding reader, shaping writer); closing dst sends the FIN.
func relay(ctx context.Context, stream *quic.Stream, src io.Reader, dst io.WriteCloser, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(conn, src) //nolint:errcheck
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite() //nolint:errcheck
		} else {
			conn.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(dst, conn) //nolint:errcheck
		dst.Close()        // FIN: data written so far is still delivered
		done <- struct{}{}
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			// Closing conn also unblocks the conn→dst copy, which then closes dst.
			stream.CancelRead(0)
			stream.CancelWrite(0)
			conn.Close()
			return
		}
	}
	stream.CancelRead(0) // no-op if the peer already finished sending
}

// --- UDP relay ---

// udpMux demultiplexes the QUIC datagrams of one connection into UDP sessions,
// keyed by the stream ID of each session's CmdUDP control stream.
type udpMux struct {
	conn *quic.Conn
	once sync.Once

	mu       sync.Mutex
	sessions map[uint32]*udpSession
}

type udpSession struct {
	id  uint32
	pc  *net.UDPConn
	out chan *UDPDatagram
}

func newUDPMux(conn *quic.Conn) *udpMux {
	return &udpMux{conn: conn, sessions: make(map[uint32]*udpSession)}
}

// serveSession runs one UDP association until its control stream ends.
func (m *udpMux) serveSession(ctx context.Context, ctrl *quic.Stream) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("UDP listen: %v", err)
		ctrl.CancelRead(0)
		ctrl.CancelWrite(0)
		return
	}
	sess := &udpSession{
		id:  uint32(ctrl.StreamID()),
		pc:  pc,
		out: make(chan *UDPDatagram, 128),
	}

	m.mu.Lock()
	m.sessions[sess.id] = sess
	m.mu.Unlock()
	m.once.Do(func() { go m.receiveLoop(ctx) })

	// Tell the client the session is registered so its datagrams won't be dropped.
	if _, err := ctrl.Write([]byte{0x00}); err != nil {
		m.mu.Lock()
		delete(m.sessions, sess.id)
		m.mu.Unlock()
		pc.Close()
		ctrl.CancelRead(0)
		return
	}

	sctx, cancel := context.WithCancel(ctx)
	go func() {
		// The association lives as long as the client keeps the control stream open.
		io.Copy(io.Discard, ctrl) //nolint:errcheck
		cancel()
	}()
	go m.sendLoop(sctx, sess)
	go m.replyLoop(sess)

	<-sctx.Done()
	cancel()
	m.mu.Lock()
	delete(m.sessions, sess.id)
	m.mu.Unlock()
	pc.Close()
	ctrl.CancelRead(0)
	ctrl.Close()
}

// receiveLoop reads datagrams from the client and hands them to their session.
func (m *udpMux) receiveLoop(ctx context.Context) {
	for {
		data, err := m.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		d, err := DecodeUDPDatagram(data)
		if err != nil {
			continue
		}
		m.mu.Lock()
		sess := m.sessions[d.Session]
		m.mu.Unlock()
		if sess == nil {
			continue
		}
		select {
		case sess.out <- d:
		default: // session backlogged: drop, as UDP would
		}
	}
}

// sendLoop forwards the client's packets to their destinations.
func (m *udpMux) sendLoop(ctx context.Context, sess *udpSession) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-sess.out:
			addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(d.Addr, strconv.Itoa(int(d.Port))))
			if err != nil {
				continue
			}
			sess.pc.WriteToUDP(d.Payload, addr) //nolint:errcheck
		}
	}
}

// replyLoop returns packets from remote hosts to the client, tagged with their source.
func (m *udpMux) replyLoop(sess *udpSession) {
	buf := make([]byte, 65535)
	for {
		n, from, err := sess.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		t, host := addrTypeFor(from.Addr().Unmap().String())
		dg := EncodeUDPDatagram(sess.id, t, host, from.Port(), buf[:n])
		if err := m.conn.SendDatagram(dg); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				continue // drop oversized packet
			}
			return
		}
	}
}

// --- token nonce cache (replay protection) ---

// tokenCache remembers recently used auth tokens to prevent replay attacks.
// Every token carries a random nonce, so each one may open at most one QUIC connection.
type tokenCache struct {
	mu     sync.Mutex
	tokens map[[32]byte]time.Time // token → expiry
}

func newTokenCache() *tokenCache {
	tc := &tokenCache{tokens: make(map[[32]byte]time.Time)}
	go tc.cleanup()
	return tc
}

// markUsed records a token as used and returns true if it is new.
// Returns false if the token was already used (replay attack).
func (tc *tokenCache) markUsed(token [32]byte) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if _, exists := tc.tokens[token]; exists {
		return false // replay
	}
	// Keep the entry for 120s: a token is valid for at most three 30s windows.
	tc.tokens[token] = time.Now().Add(120 * time.Second)
	return true
}

func (tc *tokenCache) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		tc.mu.Lock()
		now := time.Now()
		for t, exp := range tc.tokens {
			if now.After(exp) {
				delete(tc.tokens, t)
			}
		}
		tc.mu.Unlock()
	}
}
