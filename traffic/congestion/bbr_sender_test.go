// Adapted from github.com/apernet/hysteria
// Copyright (c) Hysteria Authors
// Licensed under the Apache License, Version 2.0
// Original: https://github.com/apernet/hysteria/tree/master/core/internal/congestion

package congestion

import (
	"testing"
	"time"
)

func TestBBRStartup(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	if s.mode != bbrStartup {
		t.Fatalf("expected STARTUP mode, got %d", s.mode)
	}
	if s.pacingGain != highGain {
		t.Errorf("expected pacing gain %v, got %v", highGain, s.pacingGain)
	}
}

func TestBBRInSlowStart(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	if !s.InSlowStart() {
		t.Error("expected InSlowStart() = true in STARTUP mode")
	}
	s.mode = bbrProbeBW
	if s.InSlowStart() {
		t.Error("expected InSlowStart() = false in PROBE_BW mode")
	}
}

func TestBBRGetCongestionWindow(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	cwnd := s.GetCongestionWindow()
	if cwnd <= 0 {
		t.Errorf("congestion window must be positive, got %d", cwnd)
	}
}

func TestBBRCanSend(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	// Below window: can send
	if !s.CanSend(0) {
		t.Error("CanSend(0) should be true")
	}
	// At window: cannot send
	bigInFlight := s.GetCongestionWindow() + 1
	if s.CanSend(bigInFlight) {
		t.Error("CanSend(cwnd+1) should be false")
	}
}

func TestBBROnPacketSent(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	now := time.Now()
	s.OnPacketSent(now, 0, 1, maxDatagramSize, false)
	// Should not panic or crash
}

func TestBBROnPacketAcked(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	now := time.Now()
	s.OnPacketSent(now, 0, 1, maxDatagramSize, false)

	ackTime := now.Add(50 * time.Millisecond)
	s.OnPacketAcked(1, maxDatagramSize, 0, ackTime)

	// RTT should be measured
	if s.minRTT == 0 {
		t.Error("minRTT should be set after ack")
	}
}

func TestBBRRecovery(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	if s.InRecovery() {
		t.Error("expected not in recovery at start")
	}

	s.OnCongestionEvent(1, maxDatagramSize, 10*maxDatagramSize)
	if !s.InRecovery() {
		t.Error("expected in recovery after congestion event")
	}
}

func TestBBRProbeRTTWindowReduction(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	s.mode = bbrProbeRTT
	cwnd := s.GetCongestionWindow()
	expected := ByteCount(4) * maxDatagramSize
	if cwnd != expected {
		t.Errorf("PROBE_RTT cwnd: want %d, got %d", expected, cwnd)
	}
}

func TestBBRRetransmissionTimeout(t *testing.T) {
	s := newBBRSender(maxDatagramSize)
	s.mode = bbrProbeBW
	s.fullBandwidthReached = true

	s.OnRetransmissionTimeout(true)

	if s.mode != bbrStartup {
		t.Errorf("expected STARTUP after RTO, got %d", s.mode)
	}
	if s.congestionWindow != initialCwnd {
		t.Errorf("expected initial cwnd after RTO")
	}
}

func TestJitterWrapper(t *testing.T) {
	inner := newBBRSender(maxDatagramSize)
	cfg := JitterConfig{Fraction: 0.15, Smoothing: 0.3}
	j := newJitterWrapper(inner, cfg)

	// Jitter wrapper should always return valid window
	cwnd := j.GetCongestionWindow()
	if cwnd < 4*maxDatagramSize {
		t.Errorf("jittered cwnd too small: %d", cwnd)
	}

	// Run many samples to verify jitter stays bounded
	base := inner.GetCongestionWindow()
	for i := 0; i < 1000; i++ {
		cwnd := j.GetCongestionWindow()
		maxExpected := ByteCount(float64(base) * (1 + cfg.Fraction*2))
		if cwnd > maxExpected*2 {
			t.Errorf("jittered cwnd %d far exceeds base %d", cwnd, base)
		}
	}
}

func TestJitterWrapperDelegation(t *testing.T) {
	inner := newBBRSender(maxDatagramSize)
	j := newJitterWrapper(inner, DefaultJitterConfig)

	// Delegation checks
	if j.InSlowStart() != inner.InSlowStart() {
		t.Error("InSlowStart delegation failed")
	}
	if j.InRecovery() != inner.InRecovery() {
		t.Error("InRecovery delegation failed")
	}

	now := time.Now()
	if j.HasPacingBudget(now) != inner.HasPacingBudget(now) {
		t.Error("HasPacingBudget delegation failed")
	}
}
