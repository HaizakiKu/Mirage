package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net"
	"time"

	ech "github.com/HaizakiKu/quic-ech"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// quicClientConfig is used for outbound Mirage connections.
// TLSClientConnFactory injects a Chrome-fingerprinted TLS handshake via uTLS.
var quicClientConfig = &quic.Config{
	HandshakeIdleTimeout:    10 * time.Second, // first ACME issuance can take several seconds
	MaxIdleTimeout:          30 * time.Second,
	KeepAlivePeriod:         10 * time.Second,
	MaxIncomingStreams:       1024,
	MaxIncomingUniStreams:    16,
	EnableDatagrams:         true,
	TLSClientConnFactory:    UTLSConnFactory(utls.HelloChrome_Auto),
}

// quicServerConfig is used for inbound Mirage connections (no uTLS needed server-side).
var quicServerConfig = &quic.Config{
	MaxIdleTimeout:       30 * time.Second,
	KeepAlivePeriod:      10 * time.Second,
	MaxIncomingStreams:    1024,
	MaxIncomingUniStreams: 16,
	EnableDatagrams:      true,
}

// ServerTLSConfig builds a tls.Config for the Mirage server.
// ALPN is set to "h3" to look like an HTTP/3 server.
// ECH keys are loaded from the provider for active-probe resistance.
func ServerTLSConfig(cert tls.Certificate, echProvider *ech.Provider) *tls.Config {
	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		NextProtos:               []string{"h3"},
		EncryptedClientHelloKeys: echProvider.Keys(),
		MinVersion:               tls.VersionTLS13,
	}
}

// ServerTLSConfigDynamic builds a tls.Config that fetches certificates on demand.
// Used for ACME mode where the cert is managed by autocert.Manager.
func ServerTLSConfigDynamic(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), echProvider *ech.Provider) *tls.Config {
	return &tls.Config{
		GetCertificate:           getCert,
		NextProtos:               []string{"h3"},
		EncryptedClientHelloKeys: echProvider.Keys(),
		MinVersion:               tls.VersionTLS13,
	}
}

// ClientTLSConfig builds a tls.Config for the Mirage client.
// If echConfigList is nil, ECH is skipped with a warning logged by the caller.
func ClientTLSConfig(serverName string, echConfigList []byte) *tls.Config {
	cfg := &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}
	if len(echConfigList) > 0 {
		cfg.EncryptedClientHelloConfigList = echConfigList
	}
	return cfg
}

// NewQUICServer creates a *quic.Listener with Mirage's QUIC config.
func NewQUICServer(addr string, tlsCfg *tls.Config) (*quic.Listener, error) {
	return quic.ListenAddr(addr, tlsCfg, quicServerConfig)
}

// newQUICListener listens on addr. With a non-nil resetKey the server answers
// packets for connections it doesn't know (e.g. from before a restart) with a
// stateless reset, so clients drop the dead connection at once instead of
// waiting for the idle timeout. The key must stay the same across restarts.
// The transport lives for the rest of the process (used by Server.Run).
func newQUICListener(addr string, tlsCfg *tls.Config, resetKey *quic.StatelessResetKey) (*quic.Listener, error) {
	ln, _, err := listenQUIC(addr, tlsCfg, resetKey)
	return ln, err
}

func listenQUIC(addr string, tlsCfg *tls.Config, resetKey *quic.StatelessResetKey) (*quic.Listener, *net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	tr := &quic.Transport{Conn: udpConn, StatelessResetKey: resetKey}
	ln, err := tr.Listen(tlsCfg, quicServerConfig)
	if err != nil {
		udpConn.Close()
		return nil, nil, err
	}
	return ln, udpConn, nil
}

// statelessResetKey derives a restart-stable reset key from the shared password.
func statelessResetKey(password string) *quic.StatelessResetKey {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("mirage stateless reset key"))
	var key quic.StatelessResetKey
	copy(key[:], mac.Sum(nil))
	return &key
}

// NewQUICClient dials a Mirage server with proper QUIC config.
// Uses a Chrome-fingerprinted TLS handshake (uTLS HelloChrome_Auto).
func NewQUICClient(ctx context.Context, addr string, tlsCfg *tls.Config) (*quic.Conn, error) {
	return quic.DialAddr(ctx, addr, tlsCfg, quicClientConfig)
}

// ParseECHConfigList decodes a base64 ECHConfigList from the config.
func ParseECHConfigList(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(b64)
}
