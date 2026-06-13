package traffic

import (
	"crypto/rand"
	"io"
	"math/big"
)

// PaddingProfile defines the target packet size distribution.
type PaddingProfile struct {
	Name string
	// Buckets define size ranges and their probability weights.
	Buckets []paddingBucket
}

type paddingBucket struct {
	min    int
	max    int
	weight int // relative weight (sum of all = total weight)
}

// Real HTTP/3 traffic distributions:
//   small  [20–100 bytes]    ~15% — headers, ACKs
//   medium [200–600 bytes]   ~20% — small responses
//   large  [1200–1400 bytes] ~65% — data frames
var browseProfile = PaddingProfile{
	Name: "browse",
	Buckets: []paddingBucket{
		{20, 100, 15},
		{200, 600, 20},
		{1200, 1400, 65},
	},
}

var videoProfile = PaddingProfile{
	Name: "video",
	Buckets: []paddingBucket{
		{20, 60, 5},
		{200, 400, 10},
		{1200, 1400, 85},
	},
}

var downloadProfile = PaddingProfile{
	Name: "download",
	Buckets: []paddingBucket{
		{20, 60, 3},
		{100, 300, 7},
		{1200, 1400, 90},
	},
}

func profileForName(name string) PaddingProfile {
	switch name {
	case "video":
		return videoProfile
	case "download":
		return downloadProfile
	default:
		return browseProfile
	}
}

const quicMaxDatagramSize = 1200

// PaddingWriter normalizes write sizes to match the target packet size distribution.
//   - Small writes: padded with random bytes to the next bucket boundary
//   - Large writes: split at packet boundaries to avoid oversized frames
//   - Padding bytes: cryptographically random (non-compressible)
//   - Never exceeds quicMaxDatagramSize
type PaddingWriter struct {
	inner   io.Writer
	profile PaddingProfile
}

func newPaddingWriter(w io.Writer, profile PaddingProfile) *PaddingWriter {
	return &PaddingWriter{inner: w, profile: profile}
}

func (p *PaddingWriter) Write(data []byte) (int, error) {
	total := len(data)
	offset := 0

	for offset < total {
		target := p.pickTargetSize()

		remaining := total - offset
		if remaining <= target {
			// Pad this chunk to target size
			chunk := make([]byte, target)
			copy(chunk, data[offset:])
			// Fill padding with random bytes so it's non-compressible
			if remaining < target {
				if _, err := rand.Read(chunk[remaining:]); err != nil {
					return offset, err
				}
			}
			if _, err := p.inner.Write(chunk); err != nil {
				return offset, err
			}
			offset += remaining
		} else {
			// Send target-sized chunk
			if _, err := p.inner.Write(data[offset : offset+target]); err != nil {
				return offset, err
			}
			offset += target
		}
	}
	return total, nil
}

func (p *PaddingWriter) Close() error {
	if c, ok := p.inner.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (p *PaddingWriter) pickTargetSize() int {
	totalWeight := 0
	for _, b := range p.profile.Buckets {
		totalWeight += b.weight
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(totalWeight)))
	pick := int(n.Int64())

	for _, b := range p.profile.Buckets {
		pick -= b.weight
		if pick < 0 {
			size := randomInRange(b.min, b.max)
			if size > quicMaxDatagramSize {
				size = quicMaxDatagramSize
			}
			return size
		}
	}
	return quicMaxDatagramSize
}

func randomInRange(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}
