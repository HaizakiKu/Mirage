package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	ech "github.com/HaizakiKu/quic-ech"
	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/masq"
	"github.com/HaizakiKu/mirage/traffic/congestion"
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

	// HTTP-01 challenge server — must listen on :80 for Let's Encrypt to reach it
	go func() {
		srv := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil)}
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("acme http-01 listener: %v", err)
		}
	}()

	log.Printf("ACME: managing certificate for %s (cache: %s)", cfg.Domain, cacheDir)
	return m.GetCertificate, nil
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
	ln, err := NewQUICServer(s.cfg.Listen, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
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

func (s *Server) handleConn(ctx context.Context, conn *quic.Conn) {
	authCtx, cancel := context.WithTimeout(ctx, s.getAuthTimeout())
	defer cancel()

	stream, err := conn.AcceptStream(authCtx)
	if err != nil {
		// No stream within timeout — active probe or idle scanner
		if serveErr := s.masqSrv.ServeQUICConn(conn); serveErr != nil {
			log.Printf("masq serve (timeout): %v", serveErr)
		}
		return
	}

	hdr, err := DecodeAuthHeader(stream)
	valid := err == nil &&
		ValidateToken(hdr.Token, s.cfg.Password) &&
		s.tokens.markUsed(hdr.Token) // replay protection: same token rejected twice

	if !valid {
		if serveErr := s.masqSrv.ServeQUICConn(conn); serveErr != nil {
			log.Printf("masq serve (bad auth): %v", serveErr)
		}
		return
	}

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
func (s *Server) handleProxy(ctx context.Context, conn *quic.Conn, firstStream *quic.Stream, h *AuthHeader) {
	switch h.Command {
	case CmdTCP:
		go s.proxyTCP(ctx, firstStream, h)
		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func(st *quic.Stream) {
				hdr, err := DecodeAuthHeader(st)
				if err != nil || !ValidateToken(hdr.Token, s.cfg.Password) {
					st.Close()
					return
				}
				s.proxyTCP(ctx, st, hdr)
			}(stream)
		}
	case CmdUDP:
		s.proxyUDP(ctx, conn, h)
	default:
		log.Printf("unknown command 0x%02x from %s", h.Command, conn.RemoteAddr())
	}
}

func (s *Server) proxyTCP(ctx context.Context, stream *quic.Stream, h *AuthHeader) {
	defer stream.Close()

	target := h.TargetAddr()
	dial := &net.Dialer{}
	conn, err := dial.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer conn.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(conn, stream); done <- struct{}{} }()    //nolint:errcheck
	go func() { io.Copy(stream, conn); done <- struct{}{} }()    //nolint:errcheck

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Server) proxyUDP(ctx context.Context, conn *quic.Conn, h *AuthHeader) {
	target := h.TargetAddr()
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("resolve UDP %s: %v", target, err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("dial UDP %s: %v", target, err)
		return
	}
	defer udpConn.Close()

	go func() {
		for {
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			udpConn.Write(data) //nolint:errcheck
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, err := udpConn.Read(buf)
		if err != nil {
			return
		}
		if err := conn.SendDatagram(buf[:n]); err != nil {
			return
		}
	}
}

// --- token nonce cache (replay protection) ---

// tokenCache remembers recently used auth tokens to prevent replay attacks.
// A token is valid for at most one QUIC connection within its 30-second bucket.
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
	// Keep the entry for 70s (covers two 30s windows + margin).
	tc.tokens[token] = time.Now().Add(70 * time.Second)
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
