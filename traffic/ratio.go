package traffic

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const defaultRatioTarget = 0.1 // 1:10 up:down — typical video streaming

// RatioBalancer monitors up/down byte counts and injects QUIC PING frames
// on the underrepresented direction to maintain the target ratio.
//
// Default target: 1:10 (up:down) — typical video streaming.
// Auto-adjusts profile based on observed traffic pattern.
type RatioBalancer struct {
	upBytes   atomic.Int64
	downBytes atomic.Int64
	target    float64
	conn      *quic.Conn
}

// NewRatioBalancer creates a RatioBalancer for the given connection.
func NewRatioBalancer(conn *quic.Conn) *RatioBalancer {
	return &RatioBalancer{
		target: defaultRatioTarget,
		conn:   conn,
	}
}

// RecordUp records bytes sent by the client (upstream direction).
func (r *RatioBalancer) RecordUp(n int) {
	r.upBytes.Add(int64(n))
}

// RecordDown records bytes received by the client (downstream direction).
func (r *RatioBalancer) RecordDown(n int) {
	r.downBytes.Add(int64(n))
}

// Run monitors the ratio and sends PING frames to adjust if needed.
func (r *RatioBalancer) Run(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.adjust()
		}
	}
}

func (r *RatioBalancer) adjust() {
	up := float64(r.upBytes.Load())
	down := float64(r.downBytes.Load())

	if down == 0 {
		return
	}

	currentRatio := up / down
	if currentRatio > r.target*2 {
		_ = r.conn.SendDatagram([]byte{0x00})
	}
}

// SetTarget sets a custom up/down ratio target.
func (r *RatioBalancer) SetTarget(ratio float64) {
	r.target = ratio
}

// AutoProfile auto-detects and sets the ratio target based on observed traffic.
func (r *RatioBalancer) AutoProfile() {
	up := float64(r.upBytes.Load())
	down := float64(r.downBytes.Load())
	if down == 0 {
		return
	}
	observed := up / down
	switch {
	case observed < 0.05:
		r.target = 0.05
	case observed < 0.15:
		r.target = 0.1
	default:
		r.target = 0.3
	}
}
