package traffic

import (
	"crypto/rand"
	"encoding/binary"
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

// paddingFrameHeaderLen is the size of the [2B payloadLen][2B padLen] frame header.
const paddingFrameHeaderLen = 4

// PaddingWriter normalizes write sizes to match the target packet size distribution.
// Every write is emitted as one or more frames:
//
//	[2B payload length][2B padding length][payload][padding]
//
// so the receiver (PaddedReader) can strip the padding again.
//   - Small writes: padded with random bytes up to the picked target size
//   - Large writes: split into target-sized frames
//   - Padding bytes: cryptographically random (non-compressible)
//   - A frame never exceeds quicMaxDatagramSize
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
		n := min(total-offset, target-paddingFrameHeaderLen)
		pad := target - paddingFrameHeaderLen - n

		frame := make([]byte, target)
		binary.BigEndian.PutUint16(frame[0:2], uint16(n))
		binary.BigEndian.PutUint16(frame[2:4], uint16(pad))
		copy(frame[paddingFrameHeaderLen:], data[offset:offset+n])
		if pad > 0 {
			if _, err := rand.Read(frame[paddingFrameHeaderLen+n:]); err != nil {
				return offset, err
			}
		}
		if _, err := p.inner.Write(frame); err != nil {
			return offset, err
		}
		offset += n
	}
	return total, nil
}

// PaddedReader strips the framing and padding added by PaddingWriter.
type PaddedReader struct {
	inner      io.Reader
	payloadRem int // payload bytes left in the current frame
	padRem     int // padding bytes left after the payload
	hdr        [paddingFrameHeaderLen]byte
}

// NewPaddedReader wraps r, which carries PaddingWriter frames.
func NewPaddedReader(r io.Reader) *PaddedReader {
	return &PaddedReader{inner: r}
}

func (r *PaddedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.payloadRem == 0 {
		if r.padRem > 0 {
			if _, err := io.CopyN(io.Discard, r.inner, int64(r.padRem)); err != nil {
				return 0, unexpectedEOF(err)
			}
			r.padRem = 0
		}
		// io.EOF here is a clean end of stream between frames
		if _, err := io.ReadFull(r.inner, r.hdr[:]); err != nil {
			return 0, err
		}
		r.payloadRem = int(binary.BigEndian.Uint16(r.hdr[0:2]))
		r.padRem = int(binary.BigEndian.Uint16(r.hdr[2:4]))
	}

	if len(p) > r.payloadRem {
		p = p[:r.payloadRem]
	}
	n, err := r.inner.Read(p)
	r.payloadRem -= n
	if err == io.EOF && (r.payloadRem > 0 || r.padRem > 0) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
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
