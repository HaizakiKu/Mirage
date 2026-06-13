// Package core — uTLS bridge for QUIC Chrome fingerprinting.
// uTLS types are structurally identical to crypto/tls but separately defined,
// so we convert event and state values between the two packages here.
package core

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"

	utls "github.com/refraction-networking/utls"
)

// uTLSConnBridge wraps *utls.UQUICConn and adapts it to the interface expected by
// quic-go's internal/handshake package (same method signatures as crypto/tls.QUICConn).
type uTLSConnBridge struct {
	conn *utls.UQUICConn
}

func (b *uTLSConnBridge) Start(ctx context.Context) error {
	return b.conn.Start(ctx)
}

// NextEvent converts utls.QUICEvent to crypto/tls.QUICEvent.
// The Kind and Level constants have identical integer values in both packages.
// SessionState is left nil: utls.UQUICConn has enableSessionEvents=false so
// QUICStoreSession/QUICResumeSession events are never emitted.
func (b *uTLSConnBridge) NextEvent() stdtls.QUICEvent {
	uev := b.conn.NextEvent()
	return stdtls.QUICEvent{
		Kind:  stdtls.QUICEventKind(uev.Kind),
		Level: stdtls.QUICEncryptionLevel(uev.Level),
		Data:  uev.Data,
		Suite: uev.Suite,
	}
}

func (b *uTLSConnBridge) Close() error {
	return b.conn.Close()
}

// HandleData converts crypto/tls.QUICEncryptionLevel to utls.QUICEncryptionLevel.
// Both are int with identical const values.
func (b *uTLSConnBridge) HandleData(level stdtls.QUICEncryptionLevel, data []byte) error {
	return b.conn.HandleData(utls.QUICEncryptionLevel(level), data)
}

func (b *uTLSConnBridge) SetTransportParameters(params []byte) {
	b.conn.SetTransportParameters(params)
}

// StoreSession is a no-op: UQUICConn doesn't support session storage.
// This sacrifices 0-RTT resumption but preserves the Chrome fingerprint.
func (b *uTLSConnBridge) StoreSession(_ *stdtls.SessionState) error {
	return nil
}

func (b *uTLSConnBridge) SendSessionTicket(opts stdtls.QUICSessionTicketOptions) error {
	return b.conn.SendSessionTicket(utls.QUICSessionTicketOptions{
		EarlyData: opts.EarlyData,
		Extra:     opts.Extra,
	})
}

// ConnectionState copies fields from utls.ConnectionState to crypto/tls.ConnectionState.
// PeerApplicationSettings (utls-only) and ekm (unexported) are dropped.
func (b *uTLSConnBridge) ConnectionState() stdtls.ConnectionState {
	u := b.conn.ConnectionState()
	cs := stdtls.ConnectionState{
		Version:                     u.Version,
		HandshakeComplete:           u.HandshakeComplete,
		DidResume:                   u.DidResume,
		CipherSuite:                 u.CipherSuite,
		NegotiatedProtocol:          u.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  u.NegotiatedProtocolIsMutual,
		ServerName:                  u.ServerName,
		SignedCertificateTimestamps: u.SignedCertificateTimestamps,
		OCSPResponse:                u.OCSPResponse,
		TLSUnique:                   u.TLSUnique,
		ECHAccepted:                 u.ECHAccepted,
	}
	// x509.Certificate is the same stdlib type in both packages.
	if len(u.PeerCertificates) > 0 {
		cs.PeerCertificates = make([]*x509.Certificate, len(u.PeerCertificates))
		for i, c := range u.PeerCertificates {
			cs.PeerCertificates[i] = c
		}
	}
	if len(u.VerifiedChains) > 0 {
		cs.VerifiedChains = make([][]*x509.Certificate, len(u.VerifiedChains))
		for i, chain := range u.VerifiedChains {
			cs.VerifiedChains[i] = make([]*x509.Certificate, len(chain))
			for j, c := range chain {
				cs.VerifiedChains[i][j] = c
			}
		}
	}
	return cs
}

// adaptTLSConfig copies the fields Mirage sets from *crypto/tls.Config to *utls.Config.
func adaptTLSConfig(src *stdtls.Config) *utls.Config {
	dst := &utls.Config{
		ServerName:                     src.ServerName,
		NextProtos:                     src.NextProtos,
		InsecureSkipVerify:             src.InsecureSkipVerify,
		MinVersion:                     src.MinVersion,
		RootCAs:                        src.RootCAs,
		EncryptedClientHelloConfigList: src.EncryptedClientHelloConfigList,
	}
	if src.SessionTicketsDisabled {
		dst.SessionTicketsDisabled = true
	}
	return dst
}

// UTLSConnFactory returns a factory function suitable for quic.Config.TLSClientConnFactory.
// Each call creates a new *uTLSConnBridge with the given ClientHelloID,
// making the QUIC handshake look like a real browser to DPI systems.
func UTLSConnFactory(helloID utls.ClientHelloID) func(*stdtls.QUICConfig) any {
	return func(cfg *stdtls.QUICConfig) any {
		uConn := utls.UQUICClient(
			&utls.QUICConfig{TLSConfig: adaptTLSConfig(cfg.TLSConfig)},
			helloID,
		)
		return &uTLSConnBridge{conn: uConn}
	}
}
