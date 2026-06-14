package core

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"time"

	ech "github.com/HaizakiKu/quic-ech"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// quicClientConfig is used for outbound Mirage connections.
// TLSClientConnFactory injects a Chrome-fingerprinted TLS handshake via uTLS.
var quicClientConfig = &quic.Config{
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
