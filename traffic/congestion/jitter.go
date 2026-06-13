package congestion

import (
	"math/rand"
	"sync"
	"time"
)

// JitterConfig controls the jitter parameters for Mirage's anti-fingerprint layer.
type JitterConfig struct {
	// Fraction is the ±jitter fraction, e.g. 0.15 for ±15%.
	Fraction float64
	// Smoothing is the EMA coefficient, e.g. 0.3 (lower = smoother transitions).
	Smoothing float64
}

// DefaultJitterConfig is the recommended configuration for anti-censorship use.
var DefaultJitterConfig = JitterConfig{
	Fraction:  0.15,
	Smoothing: 0.3,
}

// jitterWrapper wraps any CongestionControl and adds smooth random rate
// perturbation via exponential moving average (EMA).
//
// Rate = BBR_rate × (1 + currentJitter)
// currentJitter = EMA(currentJitter, random(-Fraction, +Fraction))
//
// EMA smoothing prevents step-function jumps that would be detectable.
// The result is a gently drifting rate curve that mimics human-driven browsing
// behaviour rather than mechanical BBR's flat throughput line.
type jitterWrapper struct {
	inner         congestionControlEx
	cfg           JitterConfig
	currentJitter float64
	rng           *rand.Rand
	mu            sync.Mutex
}

func newJitterWrapper(inner congestionControlEx, cfg JitterConfig) *jitterWrapper {
	if cfg.Smoothing <= 0 || cfg.Smoothing >= 1 {
		cfg.Smoothing = DefaultJitterConfig.Smoothing
	}
	if cfg.Fraction <= 0 || cfg.Fraction > 0.5 {
		cfg.Fraction = DefaultJitterConfig.Fraction
	}
	return &jitterWrapper{
		inner: inner,
		cfg:   cfg,
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// advanceJitter steps the EMA. Must be called with mu held.
func (j *jitterWrapper) advanceJitter() {
	sample := (j.rng.Float64()*2 - 1) * j.cfg.Fraction
	// EMA: currentJitter = α × sample + (1 - α) × currentJitter
	j.currentJitter = j.cfg.Smoothing*sample + (1-j.cfg.Smoothing)*j.currentJitter
}

func (j *jitterWrapper) jitterScale() float64 {
	return 1.0 + j.currentJitter
}

// applyJitter applies the current jitter multiplier to a ByteCount.
func (j *jitterWrapper) applyJitter(v ByteCount) ByteCount {
	scale := j.jitterScale()
	result := ByteCount(float64(v) * scale)
	if result < 1 {
		result = 1
	}
	return result
}

// --- congestionControlEx interface ---

func (j *jitterWrapper) OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, pktNum PacketNumber, bytes ByteCount, isAck bool) {
	j.inner.OnPacketSent(sentTime, bytesInFlight, pktNum, bytes, isAck)
}

func (j *jitterWrapper) CanSend(bytesInFlight ByteCount) bool {
	return j.inner.CanSend(bytesInFlight)
}

func (j *jitterWrapper) GetCongestionWindow() ByteCount {
	j.mu.Lock()
	j.advanceJitter()
	scale := j.jitterScale()
	j.mu.Unlock()

	base := j.inner.GetCongestionWindow()
	result := ByteCount(float64(base) * scale)
	if result < 4*maxDatagramSize {
		result = 4 * maxDatagramSize
	}
	return result
}

func (j *jitterWrapper) OnPacketAcked(pktNum PacketNumber, ackedBytes ByteCount, priorInFlight ByteCount, eventTime time.Time) {
	j.inner.OnPacketAcked(pktNum, ackedBytes, priorInFlight, eventTime)
}

func (j *jitterWrapper) OnCongestionEvent(pktNum PacketNumber, lostBytes ByteCount, priorInFlight ByteCount) {
	j.inner.OnCongestionEvent(pktNum, lostBytes, priorInFlight)
}

func (j *jitterWrapper) OnRetransmissionTimeout(packetsRetransmitted bool) {
	j.inner.OnRetransmissionTimeout(packetsRetransmitted)
}

func (j *jitterWrapper) MaybeExitSlowStart() {
	j.inner.MaybeExitSlowStart()
}

func (j *jitterWrapper) InSlowStart() bool {
	return j.inner.InSlowStart()
}

func (j *jitterWrapper) InRecovery() bool {
	return j.inner.InRecovery()
}

func (j *jitterWrapper) HasPacingBudget(now time.Time) bool {
	return j.inner.HasPacingBudget(now)
}

func (j *jitterWrapper) TimeUntilSend() time.Time {
	return j.inner.TimeUntilSend()
}

// PacingRate returns the jitter-adjusted pacing rate for the given base rate.
// Used when the congestion window method isn't sufficient to convey pacing.
func (j *jitterWrapper) PacingRate(base Bandwidth) Bandwidth {
	j.mu.Lock()
	scale := j.jitterScale()
	j.mu.Unlock()
	return Bandwidth(float64(base) * scale)
}
