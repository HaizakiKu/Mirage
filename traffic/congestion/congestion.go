// Adapted from github.com/apernet/hysteria
// Copyright (c) Hysteria Authors
// Licensed under the Apache License, Version 2.0
// Original: https://github.com/apernet/hysteria/tree/master/core/internal/congestion

package congestion

import (
	"time"

	"github.com/quic-go/quic-go"
)

// ccSetter is the interface that quic-go's *Conn must satisfy for
// custom congestion control injection. This matches quic-go's internal
// SetCongestionControlEx method exposed on the concrete *Conn type.
//
// NOTE: This type assertion requires quic-go to expose SetCongestionControlEx.
// With vanilla quic-go v0.57.1, this method may not be present; use a fork
// that exports it if needed. See go.mod for the replace directive comment.
type ccSetter interface {
	SetCongestionControlEx(cc congestionControlEx)
}

// congestionControlEx is the interface that must match quic-go's internal
// congestion.CongestionControlEx interface exactly.
type congestionControlEx interface {
	OnPacketSent(time.Time, ByteCount, PacketNumber, ByteCount, bool)
	CanSend(ByteCount) bool
	GetCongestionWindow() ByteCount
	OnPacketAcked(PacketNumber, ByteCount, ByteCount, time.Time)
	OnCongestionEvent(PacketNumber, ByteCount, ByteCount)
	OnRetransmissionTimeout(bool)
	MaybeExitSlowStart()
	InSlowStart() bool
	InRecovery() bool
	HasPacingBudget(time.Time) bool
	TimeUntilSend() time.Time
}

// Ensure our senders implement the interface.
var _ congestionControlEx = (*bbrSender)(nil)
var _ congestionControlEx = (*jitterWrapper)(nil)

// UseBBR sets Hysteria2-adapted BBR as the congestion controller for conn.
// Adapted from github.com/apernet/hysteria (Apache 2.0).
func UseBBR(conn *quic.Conn) {
	sender := newBBRSender(maxDatagramSize)
	setCC(conn, sender)
}

// UseJitteredBBR sets BBR + smooth EMA jitter as the congestion controller.
// This is Mirage's extension on top of Hysteria2's BBR for anti-censorship use.
// Call this instead of UseBBR() to obscure the mechanical flat-throughput BBR signature.
func UseJitteredBBR(conn *quic.Conn, cfg JitterConfig) {
	sender := newBBRSender(maxDatagramSize)
	jittered := newJitterWrapper(sender, cfg)
	setCC(conn, jittered)
}

func setCC(conn *quic.Conn, cc congestionControlEx) {
	if s, ok := any(conn).(ccSetter); ok {
		s.SetCongestionControlEx(cc)
	}
}
