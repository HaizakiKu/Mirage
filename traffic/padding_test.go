package traffic

import (
	"bytes"
	"testing"
)

// TestPacketSizeDistribution verifies the browse profile bucket probabilities
// using a chi-squared goodness-of-fit test.
//
// Buckets (browse profile):
//
//	small  [20,  100]:  15%  (p=0.15)
//	medium [200, 600]:  20%  (p=0.20)
//	large  [1200,1400]: 65%  (p=0.65) — capped at 1200 by MTU
//
// χ² critical value for df=2 at α=0.05: 5.991
func TestPacketSizeDistribution(t *testing.T) {
	// n=2000 and α=0.001 (critical=13.816) give a false-positive rate < 0.01%.
	// α=0.05 (critical=5.991) would fail ~5% of the time even for a correct impl.
	const n = 2000

	var small, medium, large int
	for i := 0; i < n; i++ {
		var buf bytes.Buffer
		pw := newPaddingWriter(&buf, browseProfile)
		pw.Write([]byte("x")) //nolint:errcheck

		sz := buf.Len()
		switch {
		case sz <= 100:
			small++
		case sz <= 600:
			medium++
		default:
			large++
		}
	}

	t.Logf("small=%d medium=%d large=%d (n=%d)", small, medium, large, n)

	expected := [3]float64{0.15 * n, 0.20 * n, 0.65 * n}
	observed := [3]float64{float64(small), float64(medium), float64(large)}

	chi2 := 0.0
	for i := 0; i < 3; i++ {
		diff := observed[i] - expected[i]
		chi2 += (diff * diff) / expected[i]
	}

	t.Logf("χ²=%.3f (critical=13.816 at α=0.001, df=2)", chi2)

	const critical = 13.816 // α=0.001, df=2
	if chi2 > critical {
		t.Errorf("packet size distribution does not match browse profile: χ²=%.3f > %.3f", chi2, critical)
	}
}

// sizeTracker records the size of each individual Write call.
type sizeTracker struct {
	sizes []int
}

func (s *sizeTracker) Write(p []byte) (int, error) {
	s.sizes = append(s.sizes, len(p))
	return len(p), nil
}

// TestPaddingMTUCap verifies no individual padded packet exceeds quicMaxDatagramSize.
// PaddingWriter may split a single Write call into multiple per-packet writes;
// what matters is that each individual inner.Write never exceeds the MTU cap.
func TestPaddingMTUCap(t *testing.T) {
	for i := 0; i < 500; i++ {
		st := &sizeTracker{}
		pw := newPaddingWriter(st, browseProfile)
		input := make([]byte, (i%200)+1)
		pw.Write(input) //nolint:errcheck

		for _, sz := range st.sizes {
			if sz > quicMaxDatagramSize {
				t.Errorf("i=%d: individual padded write %d > MTU cap %d", i, sz, quicMaxDatagramSize)
			}
		}
	}
}
