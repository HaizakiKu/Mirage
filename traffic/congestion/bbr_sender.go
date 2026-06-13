// Adapted from github.com/apernet/hysteria
// Copyright (c) Hysteria Authors
// Licensed under the Apache License, Version 2.0
// Original: https://github.com/apernet/hysteria/tree/master/core/internal/congestion

package congestion

import (
	"math"
	"math/rand"
	"time"
)

// ByteCount mirrors quic-go/internal/protocol.ByteCount (int64 underlying type).
type ByteCount int64

// PacketNumber mirrors quic-go/internal/protocol.PacketNumber (int64 underlying type).
type PacketNumber int64

// Bandwidth in bytes per second.
type Bandwidth int64

const (
	infBandwidth Bandwidth = math.MaxInt64

	maxDatagramSize ByteCount = 1252
	initialCwnd     ByteCount = 32 * maxDatagramSize

	// BBR gains
	highGain             = 2.885    // ln(2) ≈ 2.885 for STARTUP
	drainGain            = 1 / 2.885
	probeBWCycleLength   = 8
	startupGrowthTarget  = 1.25
	maxStartupFullRounds = 3

	minRTTWindowDuration = 10 * time.Second
	probeRTTDuration     = 200 * time.Millisecond
)

var probeBWPacingGains = [probeBWCycleLength]float64{
	1.25, 0.75, 1, 1, 1, 1, 1, 1,
}

type bbrMode int

const (
	bbrStartup  bbrMode = iota
	bbrDrain
	bbrProbeBW
	bbrProbeRTT
)

type recoveryState int

const (
	recoveryNotStarted recoveryState = iota
	recoveryConservation
	recoveryGrowth
)

// windowedFilter tracks a windowed max or min over a sliding window of rounds.
type windowedFilter struct {
	windowLen int64
	best      [3]Bandwidth
	bestTime  [3]int64
	currTime  int64
}

func newWindowedFilter(windowLen int64) *windowedFilter {
	return &windowedFilter{windowLen: windowLen}
}

func (f *windowedFilter) update(sample Bandwidth, now int64) {
	if f.best[0] == 0 || sample >= f.best[0] || now-f.bestTime[2] > f.windowLen {
		f.best[0] = sample
		f.best[1] = sample
		f.best[2] = sample
		f.bestTime[0] = now
		f.bestTime[1] = now
		f.bestTime[2] = now
		f.currTime = now
		return
	}

	if sample >= f.best[1] {
		f.best[1] = sample
		f.best[2] = sample
		f.bestTime[1] = now
		f.bestTime[2] = now
	} else if sample >= f.best[2] {
		f.best[2] = sample
		f.bestTime[2] = now
	}

	if now-f.bestTime[0] > f.windowLen {
		f.best[0] = f.best[1]
		f.bestTime[0] = f.bestTime[1]
		f.best[1] = f.best[2]
		f.bestTime[1] = f.bestTime[2]
		f.best[2] = sample
		f.bestTime[2] = now
		if now-f.bestTime[0] > f.windowLen {
			f.best[0] = f.best[1]
			f.bestTime[0] = f.bestTime[1]
			f.best[1] = f.best[2]
			f.bestTime[1] = f.bestTime[2]
			f.best[2] = sample
			f.bestTime[2] = now
		}
	} else if f.bestTime[1] == f.bestTime[0] && now-f.bestTime[1] > f.windowLen/4 {
		f.best[2] = sample
		f.best[1] = sample
		f.bestTime[2] = now
		f.bestTime[1] = now
	} else if f.bestTime[2] == f.bestTime[1] && now-f.bestTime[2] > f.windowLen/2 {
		f.best[2] = sample
		f.bestTime[2] = now
	}
}

func (f *windowedFilter) get() Bandwidth { return f.best[0] }

// bandwidthSampler estimates bandwidth from acked packets.
type bandwidthSampler struct {
	totalBytesSent        ByteCount
	totalBytesAcked       ByteCount
	totalBytesSentAtLastAck ByteCount
	lastAckedPacketSentTime time.Time
	lastAckedPacketAckTime  time.Time
	isAppLimited            bool
	endOfAppLimitedPhase    PacketNumber
}

func (s *bandwidthSampler) onPacketSent(sentTime time.Time, size ByteCount, pktNum PacketNumber) {
	s.totalBytesSent += size
	_ = pktNum
	_ = sentTime
}

func (s *bandwidthSampler) onPacketAcked(ackTime time.Time, sentTime time.Time, ackedBytes ByteCount, priorInFlight ByteCount) Bandwidth {
	s.totalBytesAcked += ackedBytes

	rtt := ackTime.Sub(sentTime)
	if rtt <= 0 {
		return 0
	}

	// Simple bandwidth estimate: bytes / time
	bw := Bandwidth(float64(ackedBytes) / rtt.Seconds())
	return bw
}

// bbrSender implements BBR congestion control adapted from Hysteria2/Chromium.
type bbrSender struct {
	mode bbrMode
	rng  *rand.Rand

	// Bandwidth estimation
	maxBandwidth *windowedFilter
	sampler      *bandwidthSampler

	// RTT tracking
	minRTT          time.Duration
	minRTTTimestamp time.Time
	lastRTT         time.Duration

	// Pacing
	pacingRate Bandwidth
	pacingGain float64

	// Congestion window
	congestionWindow ByteCount
	cwndGain         float64
	maxCwnd          ByteCount

	// Round tracking
	currentRoundTripEnd PacketNumber
	roundTripCount      int64
	lastSentPacket      PacketNumber

	// Startup
	fullBandwidthReached bool
	fullBandwidthCount   int
	bandwidthAtLastRound Bandwidth

	// PROBE_BW cycle
	cycleCurrentOffset int
	lastCycleStart     time.Time

	// PROBE_RTT
	probingForRTT       bool
	probeRTTRoundsDone  int
	probeRTTEndTime     time.Time
	minRTTSinceLastProbe time.Duration

	// Recovery
	recoveryState  recoveryState
	recoveryWindow ByteCount
	endRecoveryAt  PacketNumber

	// Loss
	bytesLost ByteCount

	// Timing
	lastSentTime time.Time
}

func newBBRSender(initialMaxDatagramSize ByteCount) *bbrSender {
	s := &bbrSender{
		mode:             bbrStartup,
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
		maxBandwidth:     newWindowedFilter(10),
		sampler:          &bandwidthSampler{},
		minRTT:           math.MaxInt64,
		minRTTTimestamp:  time.Now(),
		pacingGain:       highGain,
		cwndGain:         highGain,
		congestionWindow: initialCwnd,
		maxCwnd:          initialCwnd * 100,
	}
	s.minRTTSinceLastProbe = math.MaxInt64
	return s
}

func (s *bbrSender) bandwidthEstimate() Bandwidth {
	bw := s.maxBandwidth.get()
	if bw == 0 {
		return Bandwidth(initialCwnd) // bootstrap estimate
	}
	return bw
}

func (s *bbrSender) targetCongestionWindow(gain float64) ByteCount {
	bw := s.bandwidthEstimate()
	rtt := s.minRTT
	if rtt == math.MaxInt64 || rtt == 0 {
		rtt = 100 * time.Millisecond
	}
	bdp := ByteCount(float64(bw) * rtt.Seconds())
	cwnd := ByteCount(gain * float64(bdp))
	if cwnd < 4*maxDatagramSize {
		cwnd = 4 * maxDatagramSize
	}
	return cwnd
}

func (s *bbrSender) updatePacingRate() {
	bw := s.bandwidthEstimate()
	s.pacingRate = Bandwidth(float64(bw) * s.pacingGain)
	if s.pacingRate == 0 {
		s.pacingRate = Bandwidth(float64(initialCwnd) * float64(time.Second) / float64(100*time.Millisecond))
	}
}

// --- CongestionControl interface methods ---

func (s *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, pktNum PacketNumber, bytes ByteCount, isAck bool) {
	s.lastSentPacket = pktNum
	s.lastSentTime = sentTime
	s.sampler.onPacketSent(sentTime, bytes, pktNum)
}

func (s *bbrSender) CanSend(bytesInFlight ByteCount) bool {
	return bytesInFlight < s.GetCongestionWindow()
}

func (s *bbrSender) GetCongestionWindow() ByteCount {
	if s.mode == bbrProbeRTT {
		return 4 * maxDatagramSize
	}
	if s.recoveryState != recoveryNotStarted && s.recoveryWindow < s.congestionWindow {
		return s.recoveryWindow
	}
	return s.congestionWindow
}

func (s *bbrSender) OnPacketAcked(pktNum PacketNumber, ackedBytes ByteCount, priorInFlight ByteCount, eventTime time.Time) {
	rtt := eventTime.Sub(s.lastSentTime)
	if rtt > 0 && rtt < s.minRTT {
		s.minRTT = rtt
		s.minRTTTimestamp = eventTime
	}
	if rtt > 0 && rtt < s.minRTTSinceLastProbe {
		s.minRTTSinceLastProbe = rtt
	}
	if rtt > 0 {
		s.lastRTT = rtt
	}

	bw := s.sampler.onPacketAcked(eventTime, s.lastSentTime, ackedBytes, priorInFlight)
	if bw > 0 {
		s.maxBandwidth.update(bw, s.roundTripCount)
	}

	s.updateRoundTripCounter(pktNum)
	s.updateBandwidthAndMinRTT(eventTime)
	s.updateCongestionWindow(ackedBytes)

	// Exit recovery
	if s.recoveryState != recoveryNotStarted && pktNum >= s.endRecoveryAt {
		s.recoveryState = recoveryNotStarted
	}
}

func (s *bbrSender) updateRoundTripCounter(pktNum PacketNumber) {
	if pktNum >= s.currentRoundTripEnd {
		s.roundTripCount++
		s.currentRoundTripEnd = s.lastSentPacket
	}
}

func (s *bbrSender) updateBandwidthAndMinRTT(now time.Time) {
	switch s.mode {
	case bbrStartup:
		s.checkIfFullBandwidthReached()
		if s.fullBandwidthReached {
			s.enterDrainMode()
		}
	case bbrDrain:
		// Exit drain when inflight ≤ BDP
		target := s.targetCongestionWindow(1.0)
		if s.congestionWindow <= target {
			s.enterProbeBWMode(now)
		}
	case bbrProbeBW:
		s.updateProbeBWCyclePhase(now)
	case bbrProbeRTT:
		s.handleProbeRTT(now)
	}

	// Re-enter PROBE_RTT periodically
	if s.mode != bbrProbeRTT && now.Sub(s.minRTTTimestamp) > minRTTWindowDuration {
		s.enterProbeRTTMode(now)
	}
}

func (s *bbrSender) checkIfFullBandwidthReached() {
	bw := s.bandwidthEstimate()
	if bw >= Bandwidth(float64(s.bandwidthAtLastRound)*startupGrowthTarget) {
		s.bandwidthAtLastRound = bw
		s.fullBandwidthCount = 0
		return
	}
	s.fullBandwidthCount++
	if s.fullBandwidthCount >= maxStartupFullRounds {
		s.fullBandwidthReached = true
	}
}

func (s *bbrSender) enterDrainMode() {
	s.mode = bbrDrain
	s.pacingGain = drainGain
	s.cwndGain = highGain
}

func (s *bbrSender) enterProbeBWMode(now time.Time) {
	s.mode = bbrProbeBW
	s.lastCycleStart = now
	s.cycleCurrentOffset = 1 + s.rng.Intn(probeBWCycleLength-1)
	s.pacingGain = probeBWPacingGains[s.cycleCurrentOffset]
	s.cwndGain = 2
}

func (s *bbrSender) updateProbeBWCyclePhase(now time.Time) {
	if s.minRTT == math.MaxInt64 {
		return
	}
	cycleDuration := s.minRTT
	if s.pacingGain != 1.0 {
		cycleDuration = time.Duration(float64(s.minRTT) * 1.5)
	}
	if now.Sub(s.lastCycleStart) > cycleDuration {
		s.cycleCurrentOffset = (s.cycleCurrentOffset + 1) % probeBWCycleLength
		s.lastCycleStart = now
		s.pacingGain = probeBWPacingGains[s.cycleCurrentOffset]
	}
}

func (s *bbrSender) enterProbeRTTMode(now time.Time) {
	s.mode = bbrProbeRTT
	s.pacingGain = 1
	s.cwndGain = 1
	s.probingForRTT = true
	s.probeRTTRoundsDone = 0
	s.probeRTTEndTime = now.Add(probeRTTDuration)
}

func (s *bbrSender) handleProbeRTT(now time.Time) {
	if !s.probingForRTT {
		return
	}
	if now.After(s.probeRTTEndTime) {
		s.probingForRTT = false
		if s.minRTTSinceLastProbe < s.minRTT {
			s.minRTT = s.minRTTSinceLastProbe
		}
		s.minRTTTimestamp = now
		s.minRTTSinceLastProbe = math.MaxInt64

		if s.fullBandwidthReached {
			s.enterProbeBWMode(now)
		} else {
			s.enterStartupMode()
		}
	}
}

func (s *bbrSender) enterStartupMode() {
	s.mode = bbrStartup
	s.pacingGain = highGain
	s.cwndGain = highGain
}

func (s *bbrSender) updateCongestionWindow(ackedBytes ByteCount) {
	target := s.targetCongestionWindow(s.cwndGain)

	if s.mode == bbrStartup && !s.fullBandwidthReached {
		// Allow exponential growth in startup
		s.congestionWindow += ackedBytes
		if s.congestionWindow > target*2 {
			s.congestionWindow = target * 2
		}
	} else {
		// Approach target smoothly
		if s.congestionWindow < target {
			s.congestionWindow += maxDatagramSize
		} else if s.congestionWindow > target+maxDatagramSize {
			s.congestionWindow -= maxDatagramSize
		}
	}

	if s.congestionWindow > s.maxCwnd {
		s.congestionWindow = s.maxCwnd
	}

	s.updatePacingRate()
}

func (s *bbrSender) OnCongestionEvent(pktNum PacketNumber, lostBytes ByteCount, priorInFlight ByteCount) {
	s.bytesLost += lostBytes

	if s.recoveryState == recoveryNotStarted {
		s.recoveryState = recoveryConservation
		s.endRecoveryAt = s.lastSentPacket
		s.recoveryWindow = priorInFlight - lostBytes
		if s.recoveryWindow < 2*maxDatagramSize {
			s.recoveryWindow = 2 * maxDatagramSize
		}
	}
}

func (s *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if packetsRetransmitted {
		s.mode = bbrStartup
		s.pacingGain = highGain
		s.cwndGain = highGain
		s.congestionWindow = initialCwnd
		s.fullBandwidthReached = false
		s.fullBandwidthCount = 0
	}
}

func (s *bbrSender) MaybeExitSlowStart() {}

func (s *bbrSender) InSlowStart() bool {
	return s.mode == bbrStartup
}

func (s *bbrSender) InRecovery() bool {
	return s.recoveryState != recoveryNotStarted
}

func (s *bbrSender) HasPacingBudget(now time.Time) bool {
	return true
}

func (s *bbrSender) TimeUntilSend() time.Time {
	return time.Time{}
}
