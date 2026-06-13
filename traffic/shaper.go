package traffic

import "io"

// Config configures the traffic shaper.
type Config struct {
	Profile string
	Enabled bool
}

// TrafficShaper wraps a quic.Stream's write path and applies traffic shaping.
type TrafficShaper struct {
	cfg Config
}

// New creates a TrafficShaper with the given config.
func New(cfg Config) *TrafficShaper {
	return &TrafficShaper{cfg: cfg}
}

// WrapStream wraps a stream's io.ReadWriteCloser with traffic shaping layers.
// Returns the original stream unchanged if shaping is disabled.
// The returned value shadows Write/Close; all Read calls go to the original.
func (s *TrafficShaper) WrapStream(rw io.ReadWriteCloser) io.ReadWriteCloser {
	if !s.cfg.Enabled {
		return rw
	}

	padding := newPaddingWriter(rw, profileForName(s.cfg.Profile))
	burst := newBurstController(padding)
	return &shapedStream{
		reader: rw,
		writer: burst,
	}
}

// shapedStream routes reads to the underlying stream and writes through the shaping pipeline.
type shapedStream struct {
	reader io.Reader
	writer writeCloser
}

type writeCloser interface {
	Write(p []byte) (n int, err error)
	Close() error
}

func (s *shapedStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *shapedStream) Write(p []byte) (int, error) { return s.writer.Write(p) }
func (s *shapedStream) Close() error                { return s.writer.Close() }
