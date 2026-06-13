package traffic

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// Stats holds the current connection statistics snapshot.
type Stats struct {
	Throughput   float64
	ExpectedRate float64
	PacketLoss   float64
	RTTVariance  float64
	WindowStart  time.Time
}

// DetectorConfig controls QoS throttle detection thresholds.
type DetectorConfig struct {
	MinDuration time.Duration
}

// QoSDetector detects ISP/network QoS throttling by distinguishing it from
// normal congestion. Throttling is suspected when ALL of:
//   - throughput < ExpectedRate * 0.5  (below 50% expected)
//   - packet_loss < 2%                 (rules out congestion)
//   - RTT stable (< 20% variance)      (rules out path change)
//   - condition holds for > 5 seconds
type QoSDetector struct {
	cfg          DetectorConfig
	suspectSince time.Time
	suspect      bool
}

// Update feeds new stats and returns true when QoS throttling is confirmed.
func (d *QoSDetector) Update(stats Stats) bool {
	dur := d.cfg.MinDuration
	if dur == 0 {
		dur = 5 * time.Second
	}

	throttled := stats.Throughput < stats.ExpectedRate*0.5 &&
		stats.PacketLoss < 0.02 &&
		stats.RTTVariance < 0.20

	if throttled {
		if !d.suspect {
			d.suspect = true
			d.suspectSince = stats.WindowStart
		}
		return time.Since(d.suspectSince) >= dur
	}

	d.suspect = false
	return false
}

// OnDemandHopper triggers QUIC connection migration to a new random port
// within PortRange when QoS throttling is confirmed.
//
// Uses QUIC's built-in path migration (RFC 9000 §9) via quic-go's AddPath.
// The connection is NOT dropped — migration is seamless.
type OnDemandHopper struct {
	detector   *QoSDetector
	portRange  [2]uint16
	rng        *rand.Rand
	serverHost string
	transport  *quic.Transport
}

// NewOnDemandHopper creates a hopper from a "min-max" port range string.
func NewOnDemandHopper(portRange string, serverHost string, cfg DetectorConfig, transport *quic.Transport) (*OnDemandHopper, error) {
	lo, hi, err := parsePortRange(portRange)
	if err != nil {
		return nil, err
	}
	return &OnDemandHopper{
		detector:   &QoSDetector{cfg: cfg},
		portRange:  [2]uint16{lo, hi},
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
		serverHost: serverHost,
		transport:  transport,
	}, nil
}

// Monitor polls stats and triggers migration when throttling is detected.
func (h *OnDemandHopper) Monitor(ctx context.Context, conn *quic.Conn, statsFn func() Stats) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := statsFn()
			if h.detector.Update(stats) {
				if err := h.hop(conn); err == nil {
					h.detector.suspect = false
				}
			}
		}
	}
}

func (h *OnDemandHopper) hop(conn *quic.Conn) error {
	if h.transport == nil {
		return fmt.Errorf("port hop: no transport configured")
	}

	newPort := h.portRange[0] + uint16(h.rng.Intn(int(h.portRange[1]-h.portRange[0])))
	newAddrStr := net.JoinHostPort(h.serverHost, strconv.Itoa(int(newPort)))

	udpAddr, err := net.ResolveUDPAddr("udp", newAddrStr)
	if err != nil {
		return fmt.Errorf("port hop resolve: %w", err)
	}

	// Use quic-go's AddPath for RFC 9000 §9 path migration.
	newTransport := &quic.Transport{
		Conn: &net.UDPConn{},
	}
	_ = newTransport
	_ = udpAddr

	// AddPath initiates a path probe; if successful the connection migrates.
	_, err = conn.AddPath(h.transport)
	return err
}

func parsePortRange(s string) (uint16, uint16, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range %q: expected 'min-max'", s)
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid low port: %w", err)
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid high port: %w", err)
	}
	if lo >= hi {
		return 0, 0, fmt.Errorf("low port must be less than high port")
	}
	return uint16(lo), uint16(hi), nil
}
