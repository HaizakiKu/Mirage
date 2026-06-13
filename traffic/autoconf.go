package traffic

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	probeDuration    = 3 * time.Second
	probePayloadSize = 8192
)

// BandwidthProbe holds the result of an initial bandwidth measurement.
type BandwidthProbe struct {
	UploadBPS   float64
	DownloadBPS float64
}

// ProbeBandwidth sends a burst of data and measures throughput.
// Called once at connection startup to seed the congestion controller's
// expected rate and the RatioBalancer's target.
func ProbeBandwidth(ctx context.Context, conn *quic.Conn) (BandwidthProbe, error) {
	probeCtx, cancel := context.WithTimeout(ctx, probeDuration*2)
	defer cancel()

	uploadBPS, err := probeUpload(probeCtx, conn)
	if err != nil {
		return BandwidthProbe{}, err
	}

	return BandwidthProbe{
		UploadBPS:   uploadBPS,
		DownloadBPS: uploadBPS * 10,
	}, nil
}

func probeUpload(ctx context.Context, conn *quic.Conn) (float64, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	payload := make([]byte, probePayloadSize)
	start := time.Now()
	deadline := start.Add(probeDuration)

	var bytesSent int64
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			goto done
		default:
		}
		n, err := stream.Write(payload)
		bytesSent += int64(n)
		if err != nil {
			break
		}
	}

done:
	elapsed := time.Since(start).Seconds()
	if elapsed == 0 {
		return 0, nil
	}
	return float64(bytesSent) / elapsed, nil
}

// StatsCollector tracks live throughput stats for the QoSDetector.
type StatsCollector struct {
	conn         *quic.Conn
	expected     float64
	windowStart  time.Time
	windowBytes  int64
	lostPackets  int64
	totalPackets int64
}

// NewStatsCollector creates a collector with the given expected bandwidth.
func NewStatsCollector(conn *quic.Conn, expectedBPS float64) *StatsCollector {
	return &StatsCollector{
		conn:        conn,
		expected:    expectedBPS,
		windowStart: time.Now(),
	}
}

// RecordSent records bytes sent in the current window.
func (sc *StatsCollector) RecordSent(n int) {
	sc.windowBytes += int64(n)
	sc.totalPackets++
}

// RecordLost records a lost packet.
func (sc *StatsCollector) RecordLost() {
	sc.lostPackets++
	sc.totalPackets++
}

// Snapshot returns the current stats and resets the window.
func (sc *StatsCollector) Snapshot() Stats {
	now := time.Now()
	elapsed := now.Sub(sc.windowStart).Seconds()

	var throughput float64
	if elapsed > 0 {
		throughput = float64(sc.windowBytes) / elapsed
	}

	var loss float64
	if sc.totalPackets > 0 {
		loss = float64(sc.lostPackets) / float64(sc.totalPackets)
	}

	stats := Stats{
		Throughput:   throughput,
		ExpectedRate: sc.expected,
		PacketLoss:   loss,
		RTTVariance:  0, // quic-go ConnectionState does not expose RTT variance
		WindowStart:  sc.windowStart,
	}

	sc.windowStart = now
	sc.windowBytes = 0

	return stats
}
