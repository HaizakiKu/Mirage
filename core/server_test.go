package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	echpkg "github.com/HaizakiKu/quic-ech"
	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/masq"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

//test infrastructure

const testPassword = "test-password-mirage"

// testEnv holds a running Mirage server and helpers for connecting to it
type testEnv struct {
	t           *testing.T
	serverAddr  string
	certPool    *x509.CertPool
	cert        tls.Certificate
	echConfigList []byte
	cancel      context.CancelFunc
	server      *Server
}

// mockMasq is a masqHandler that records calls via a channel
type mockMasq struct {
	called chan *quic.Conn
}

func newMockMasq() *mockMasq { return &mockMasq{called: make(chan *quic.Conn, 8)} }

func (m *mockMasq) ServeQUICConn(conn *quic.Conn) error {
	m.called <- conn
	return nil
}

// newTestEnv starts a full Mirage server with an in-memory masquerade backend
// authTimeout overrides the default 5s, pass 0 for the default
func newTestEnv(t *testing.T, authTimeout time.Duration) *testEnv {
	t.Helper()

	cert, certPool := generateTestCert(t)

	// ECH provider
	echProv, err := echpkg.NewProvider("example.com", "")
	if err != nil {
		t.Fatalf("ECH provider: %v", err)
	}

	// Build masquerade cache from static in-memory content (no HTTP round-trip)
	// This avoids port-reuse collisions on Windows during tests
	cache := masq.NewStaticCacheInMemory([]byte("<html><body>masquerade</body></html>"))

	cfg := &config.ServerConfig{
		Password: testPassword,
		Traffic:  config.TrafficConfig{Profile: "browse"},
	}

	srv := newServerInternal(cfg, cert, masq.NewServer(cache), echProv)
	if authTimeout > 0 {
		srv.authTimeout = authTimeout
	}

	// Start on a random UDP port
	tlsCfg := ServerTLSConfig(cert, echProv)
	ln, err := NewQUICServer("127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
			t.Logf("server exited: %v", err)
		}
	}()
	t.Cleanup(cancel)

	return &testEnv{
		t:             t,
		serverAddr:    serverAddr,
		certPool:      certPool,
		cert:          cert,
		echConfigList: echProv.ConfigList(),
		cancel:        cancel,
		server:        srv,
	}
}

// newTestEnvWithMock is like newTestEnv but injects a mock masquerade
func newTestEnvWithMock(t *testing.T, authTimeout time.Duration) (*testEnv, *mockMasq) {
	t.Helper()

	cert, certPool := generateTestCert(t)

	echProv, err := echpkg.NewProvider("example.com", "")
	if err != nil {
		t.Fatalf("ECH provider: %v", err)
	}

	mock := newMockMasq()

	cfg := &config.ServerConfig{
		Password: testPassword,
		Traffic:  config.TrafficConfig{Profile: "browse"},
	}

	srv := newServerInternal(cfg, cert, mock, echProv)
	if authTimeout > 0 {
		srv.authTimeout = authTimeout
	}

	tlsCfg := ServerTLSConfig(cert, echProv)
	ln, err := NewQUICServer("127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { srv.Serve(ctx, ln) }() //nolint:errcheck
	t.Cleanup(cancel)

	env := &testEnv{
		t:          t,
		serverAddr: serverAddr,
		certPool:   certPool,
		cert:       cert,
		cancel:     cancel,
		server:     srv,
	}
	return env, mock
}

// dialServer opens a raw QUIC connection to the test server
func (e *testEnv) dialServer(ctx context.Context) *quic.Conn {
	e.t.Helper()
	tlsCfg := &tls.Config{
		RootCAs:    e.certPool,
		NextProtos: []string{"h3"},
		ServerName: "localhost",
	}
	conn, err := quic.DialAddr(ctx, e.serverAddr, tlsCfg, &quic.Config{EnableDatagrams: true})
	if err != nil {
		e.t.Fatalf("dial server: %v", err)
	}
	return conn
}

// sendAuthHeader writes a valid AuthHeader to stream
func sendAuthHeader(t *testing.T, stream *quic.Stream, target string, password string) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split host:port %q: %v", target, err)
	}
	port, _ := strconv.Atoi(portStr)

	addrType, addr := AddrHostname, host
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addrType = AddrIPv4
		} else {
			addrType = AddrIPv6
		}
		addr = ip.String()
	}

	hdr := &AuthHeader{
		Version:  Version,
		Token:    MakeToken(password),
		Command:  CmdTCP,
		AddrType: addrType,
		Addr:     addr,
		Port:     uint16(port),
	}
	if _, err := stream.Write(hdr.Encode()); err != nil {
		t.Fatalf("write auth header: %v", err)
	}
}

// nextLowPort is a monotonic counter for test listener ports
// It starts at a time-derived offset in 10000-19999 to avoid TIME_WAIT collisions
// between consecutive test runs: ports used in a previous run cycle out of TIME_WAIT
// (60 s) before the same offset reappears
var nextLowPort = 10000 + int(time.Now().Unix()%10000)

// startEchoServer starts a TCP echo server on a low-numbered port (below Windows
// dynamic port range 49152+) to avoid loopback source-port collision on Windows
// Uses a monotonically advancing port so consecutive tests don't reuse the same port
func startEchoServer(t *testing.T) string {
	t.Helper()
	var ln net.Listener
	base := nextLowPort
	for ; nextLowPort < base+200; nextLowPort++ {
		var err error
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", nextLowPort))
		if err == nil {
			nextLowPort++
			break
		}
	}
	if ln == nil {
		t.Fatalf("startEchoServer: no free port in %d-%d", base, base+199)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()
	return ln.Addr().String()
}

// generateTestCert creates a self-signed cert for localhost
func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}

	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return cert, pool
}

// tests

// TestAuthValid: send a valid auth header, verify data is proxied to the target
func TestAuthValid(t *testing.T) {
	echoAddr := startEchoServer(t)
	env := newTestEnv(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := env.dialServer(ctx)
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	sendAuthHeader(t, stream, echoAddr, testPassword)

	// Send a message through the proxy; echo server returns it
	msg := []byte("hello mirage")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("echo: want %q got %q", msg, buf)
	}
}

// TestAuthInvalid: send an invalid token; server must route to masquerade
func TestAuthInvalid(t *testing.T) {
	env, mock := newTestEnvWithMock(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn := env.dialServer(ctx)
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Build a header with a wrong token
	var badToken [32]byte
	rand.Read(badToken[:]) //nolint:errcheck
	hdr := &AuthHeader{
		Version: Version, Token: badToken,
		Command: CmdTCP, AddrType: AddrHostname, Addr: "example.com", Port: 80,
	}
	stream.Write(hdr.Encode()) //nolint:errcheck

	select {
	case <-mock.called:
		// pass
	case <-time.After(2 * time.Second):
		t.Error("masquerade not triggered for invalid token")
	}
}

// TestAuthTimeout: open QUIC conn, send nothing for longer than authTimeout;
// server must route to masquerade
func TestAuthTimeout(t *testing.T) {
	const shortTimeout = 150 * time.Millisecond
	env, mock := newTestEnvWithMock(t, shortTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn := env.dialServer(ctx)
	defer conn.CloseWithError(0, "done")

	// Open no streams — wait for the auth timeout to fire
	select {
	case <-mock.called:
		// pass
	case <-time.After(shortTimeout + 500*time.Millisecond):
		t.Error("masquerade not triggered after auth timeout")
	}
}

// TestReplayProtection: the same auth token must be rejected on a second QUIC connection
func TestReplayProtection(t *testing.T) {
	echoAddr := startEchoServer(t)
	env, mock := newTestEnvWithMock(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Capture the token we'll use for both connections
	token := MakeToken(testPassword)

	buildHdr := func() *AuthHeader {
		host, portStr, _ := net.SplitHostPort(echoAddr)
		port, _ := strconv.Atoi(portStr)
		return &AuthHeader{
			Version: Version, Token: token,
			Command: CmdTCP, AddrType: AddrIPv4,
			Addr: host, Port: uint16(port),
		}
	}

	tlsCfg := &tls.Config{
		RootCAs: env.certPool, NextProtos: []string{"h3"}, ServerName: "localhost",
	}

	// First connection: auth succeeds
	conn1, err := quic.DialAddr(ctx, env.serverAddr, tlsCfg, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	st1, _ := conn1.OpenStreamSync(ctx)
	st1.Write(buildHdr().Encode()) //nolint:errcheck

	// Give server time to mark token as used
	time.Sleep(100 * time.Millisecond)
	conn1.CloseWithError(0, "done")

	// Drain any masq call from conn1 (shouldn't be there, but be safe)
	select {
	case <-mock.called:
		t.Logf("note: first connection triggered masquerade unexpectedly")
	default:
	}

	// Second connection: same token → must be rejected → masquerade
	conn2, err := quic.DialAddr(ctx, env.serverAddr, tlsCfg, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.CloseWithError(0, "done")

	st2, _ := conn2.OpenStreamSync(ctx)
	st2.Write(buildHdr().Encode()) //nolint:errcheck

	select {
	case <-mock.called:
		// pass — replay was detected and masquerade was triggered
	case <-time.After(2 * time.Second):
		t.Error("replay attack not detected: second use of same token was accepted")
	}
}

// TestECHHandshake: verifies TLSConnectionState.ECHAccepted == true
func TestECHHandshake(t *testing.T) {
	env := newTestEnv(t, 0)

	if len(env.echConfigList) == 0 {
		t.Skip("ECH config list not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Client uses ECH: inner SNI = "localhost", outer SNI = "example.com" (from ECHConfig)
	tlsCfg := &tls.Config{
		RootCAs:                        env.certPool,
		ServerName:                     "localhost",
		NextProtos:                     []string{"h3"},
		EncryptedClientHelloConfigList: env.echConfigList,
	}

	conn, err := quic.DialAddr(ctx, env.serverAddr, tlsCfg, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("dial with ECH: %v — ECHConfigList may have wrong format", err)
	}
	defer conn.CloseWithError(0, "done")

	cs := conn.ConnectionState()
	if !cs.TLS.ECHAccepted {
		t.Error("TLSConnectionState.ECHAccepted is false; ECH negotiation failed")
	} else {
		t.Log("ECH accepted")
	}
}

// TestProxyTCP: proxies a real HTTP/1.1 request through the Mirage server
func TestProxyTCP(t *testing.T) {
	// Backend HTTP server
	// Use a low-numbered port for the backend to avoid Windows loopback
	// source-port collision
	var backendLn net.Listener
	base := nextLowPort
	for ; nextLowPort < base+200; nextLowPort++ {
		var err error
		backendLn, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", nextLowPort))
		if err == nil {
			nextLowPort++
			break
		}
	}
	if backendLn == nil {
		t.Fatalf("TestProxyTCP: no free port in %d-%d", base, base+199)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "proxy-ok")
	}))
	backend.Listener = backendLn
	backend.Start()
	defer backend.Close()

	env := newTestEnv(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := env.dialServer(ctx)
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	// Target is the backend's TCP address
	host, portStr, _ := net.SplitHostPort(backend.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	hdr := &AuthHeader{
		Version: Version, Token: MakeToken(testPassword),
		Command: CmdTCP, AddrType: AddrIPv4,
		Addr: host, Port: uint16(port),
	}
	stream.Write(hdr.Encode()) //nolint:errcheck

	fmt.Fprintf(stream, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

	// Read and parse the HTTP response
	resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200 got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy-ok") {
		t.Errorf("body: want 'proxy-ok', got %q", body)
	}
}

// TestMasqueradeStatus200: unauthenticated connection must receive HTTP/3 200 OK
func TestMasqueradeStatus200(t *testing.T) {
	const shortTimeout = 150 * time.Millisecond
	env := newTestEnv(t, shortTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsCfg := &tls.Config{
		RootCAs:    env.certPool,
		NextProtos: []string{"h3"},
		ServerName: "localhost",
	}

	// Open a raw QUIC connection but open NO streams so the auth timeout fires
	conn, err := quic.DialAddr(ctx, env.serverAddr, tlsCfg, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Wait for the auth timeout + a margin so masquerade has taken over
	time.Sleep(shortTimeout + 200*time.Millisecond)

	// Reuse the same QUIC connection as an HTTP/3 client
	// The masquerade HTTP/3 server is now serving this conn
	transport := &http3.Transport{
		Dial: func(_ context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
	}
	defer transport.Close()

	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Get("https://localhost/")
	if err != nil {
		t.Fatalf("HTTP/3 GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("masquerade: want 200 OK, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "masquerade") {
		t.Errorf("masquerade body: want 'masquerade', got %q", body)
	}
	t.Logf("masquerade returned %d with body: %q", resp.StatusCode, body)
}

// TestUTLSChromeFingerprint: dials the Mirage server using the production
// NewQUICClient (which injects a Chrome-fingerprinted TLS handshake via uTLS)
// and verifies the connection completes successfully
func TestUTLSChromeFingerprint(t *testing.T) {
	env := newTestEnv(t, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ClientTLSConfig uses our standard client config (ServerName + NextProtos)
	// NewQUICClient wraps this in a uTLS Chrome-fingerprinted handshake
	tlsCfg := ClientTLSConfig("localhost", nil)
	tlsCfg.RootCAs = env.certPool

	conn, err := NewQUICClient(ctx, env.serverAddr, tlsCfg)
	if err != nil {
		t.Fatalf("NewQUICClient (uTLS Chrome): %v", err)
	}
	defer conn.CloseWithError(0, "done")

	// Open a stream and send a valid auth header to confirm the connection is usable
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	echoAddr := startEchoServer(t)
	sendAuthHeader(t, stream, echoAddr, testPassword)

	msg := []byte("utls-chrome-test")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo: want %q got %q", msg, buf)
	}
	t.Log("uTLS Chrome fingerprint handshake succeeded")
}

// TestACMECertNotReadyFailsFast: before the ACME certificate exists, handshakes
// must fail at once instead of blocking on issuance (which clients only saw as
// "timeout: no recent network activity").
func TestACMECertNotReadyFailsFast(t *testing.T) {
	cert, pool := generateTestCert(t)
	echProv, err := echpkg.NewProvider("example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	ac := newACMECert("localhost", func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		<-release // issuance in progress (e.g. HTTP-01 validation hanging)
		return &cert, nil
	})
	go ac.obtainLoop()

	ln, err := NewQUICServer("127.0.0.1:0", ServerTLSConfigDynamic(ac.GetCertificate, echProv))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()

	tlsCfg := ClientTLSConfig("localhost", nil)
	tlsCfg.RootCAs = pool
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	if _, err := NewQUICClient(ctx, ln.Addr().String(), tlsCfg); err == nil {
		t.Fatal("handshake must fail while the certificate is not ready")
	} else if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("handshake blocked %v instead of failing fast: %v", d, err)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for !ac.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := NewQUICClient(ctx, ln.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("handshake after certificate is ready: %v", err)
	}
	conn.CloseWithError(0, "") //nolint:errcheck
}

// TestStatelessResetAfterRestart: a client whose server restarted must learn
// the old connection is dead promptly, not after the idle timeout.
func TestStatelessResetAfterRestart(t *testing.T) {
	cert, pool := generateTestCert(t)
	echProv, err := echpkg.NewProvider("example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	tlsSrv := ServerTLSConfig(cert, echProv)
	key := statelessResetKey(testPassword)

	ln, udpConn, err := listenQUIC("127.0.0.1:0", tlsSrv, key)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		c, err := ln.Accept(context.Background())
		if err == nil {
			accepted <- c
		}
	}()

	tlsCfg := ClientTLSConfig("localhost", nil)
	tlsCfg.RootCAs = pool
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := NewQUICClient(ctx, addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "") //nolint:errcheck
	<-accepted

	// "Restart" like a killed process: the socket vanishes without sending
	// anything, then a new server listens on the same port with the same
	// (password-derived) key.
	udpConn.Close()
	time.Sleep(50 * time.Millisecond)
	if conn.Context().Err() != nil {
		t.Fatal("client noticed the kill before the restart; test is not exercising resets")
	}
	ln2, err := newQUICListener(addr, tlsSrv, key)
	if err != nil {
		t.Fatalf("rebind %s: %v", addr, err)
	}
	defer ln2.Close()

	// A new request: the auth header alone makes the packet large enough
	// (> 42 bytes) for the server to answer with a stateless reset.
	st, err := conn.OpenStreamSync(ctx)
	if err == nil {
		st.Write(make([]byte, 100)) //nolint:errcheck
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("client kept a dead connection after server restart")
	}
}
