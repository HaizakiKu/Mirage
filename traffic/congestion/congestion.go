// Adapted from github.com/apernet/hysteria
// Copyright (c) Hysteria Authors
// Licensed under the Apache License, Version 2.0
// Original: https://github.com/apernet/hysteria/tree/master/core/internal/congestion

package congestion

import (
	"github.com/quic-go/quic-go"
)

// Our senders implement quic-go's pluggable congestion controller interface,
// which the Mirage quic-go fork exposes via (*quic.Conn).SetCongestionControl.
// If the fork (see the replace directive in go.mod) ever drops that hook,
// this fails to compile instead of silently leaving quic-go's default Reno in place.
var (
	_ quic.CongestionControl = (*bbrSender)(nil)
	_ quic.CongestionControl = (*jitterWrapper)(nil)
)

// UseBBR sets Hysteria2-adapted BBR as the congestion controller for conn.
// Adapted from github.com/apernet/hysteria (Apache 2.0).
func UseBBR(conn *quic.Conn) {
	installBBR(conn, nil)
}

// UseJitteredBBR sets BBR + smooth EMA jitter as the congestion controller.
// This is Mirage's extension on top of Hysteria2's BBR for anti-censorship use.
// Call this instead of UseBBR() to obscure the mechanical flat-throughput BBR signature.
func UseJitteredBBR(conn *quic.Conn, cfg JitterConfig) {
	installBBR(conn, &cfg)
}

// installBBR installs BBR (optionally jittered) on conn and returns the installed controller.
// The controller takes effect before the connection sends its next packet.
func installBBR(conn *quic.Conn, jitter *JitterConfig) quic.CongestionControl {
	var cc quic.CongestionControl = newBBRSender(maxDatagramSize)
	if jitter != nil {
		cc = newJitterWrapper(cc, *jitter)
	}
	conn.SetCongestionControl(cc)
	return cc
}
