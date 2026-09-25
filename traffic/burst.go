package traffic

import (
	"io"
	"math"
	"math/rand"
	"sync"
	"time"
)

const (
	minBurstBytes = 50 * 1024  // 50 KB
	maxBurstBytes = 500 * 1024 // 500 KB
	minSilenceMs  = 200
	maxSilenceMs  = 2000
	queueBufSize  = 256
)

// BurstController shapes transmission timing to match human browsing patterns:
// [burst of data] → [reading pause] → [burst] → [pause] ...
//
// Data queued during a silence gap is released at the start of the next burst.
// This does NOT drop data.
//
// Burst size: 50KB–500KB (random)
// Silence gap: 200ms–2000ms (random, heavy-tailed distribution)
type BurstController struct {
	inner  io.WriteCloser
	queue  chan []byte
	rng    *rand.Rand
	closed chan struct{} // closed by Close
	done   chan struct{} // closed when loop exits
	once   sync.Once

	errMu sync.Mutex
	err   error // first error from inner.Write
}

func newBurstController(w io.WriteCloser) *BurstController {
	b := &BurstController{
		inner:  w,
		queue:  make(chan []byte, queueBufSize),
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go b.loop()
	return b
}

func (b *BurstController) Write(p []byte) (int, error) {
	// Copy the slice since the caller may reuse the buffer.
	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case b.queue <- buf:
		return len(p), nil
	case <-b.closed:
		return 0, io.ErrClosedPipe
	case <-b.done:
		// loop stopped after an inner write error; don't block forever
		if err := b.loadErr(); err != nil {
			return 0, err
		}
		return 0, io.ErrClosedPipe
	}
}

// Close flushes all queued data to the inner writer, then closes it.
func (b *BurstController) Close() error {
	b.once.Do(func() { close(b.closed) })
	<-b.done
	return b.inner.Close()
}

func (b *BurstController) loadErr() error {
	b.errMu.Lock()
	defer b.errMu.Unlock()
	return b.err
}

func (b *BurstController) write(chunk []byte) bool {
	if _, err := b.inner.Write(chunk); err != nil {
		b.errMu.Lock()
		b.err = err
		b.errMu.Unlock()
		return false
	}
	return true
}

// drain writes out everything still queued. Called once Close was requested.
func (b *BurstController) drain() {
	for {
		select {
		case chunk := <-b.queue:
			if !b.write(chunk) {
				return
			}
		default:
			return
		}
	}
}

func (b *BurstController) loop() {
	defer close(b.done)

	for {
		// Burst phase: send up to burstSize bytes
		burstSize := minBurstBytes + b.rng.Intn(maxBurstBytes-minBurstBytes)
		sent := 0

		for sent < burstSize {
			var chunk []byte
			if sent == 0 {
				// Idle: wait for data to start the next burst.
				select {
				case chunk = <-b.queue:
				case <-b.closed:
					b.drain()
					return
				}
			} else {
				// Mid-burst: end the burst if the queue stays empty briefly.
				select {
				case chunk = <-b.queue:
				case <-time.After(5 * time.Millisecond):
					goto silence
				case <-b.closed:
					b.drain()
					return
				}
			}
			if !b.write(chunk) {
				return
			}
			sent += len(chunk)
		}

	silence:
		// Silence phase: hold data in queue for a random pause
		silenceMs := minSilenceMs + b.heavyTailRand(maxSilenceMs-minSilenceMs)
		select {
		case <-time.After(time.Duration(silenceMs) * time.Millisecond):
		case <-b.closed:
			b.drain()
			return
		}
	}
}

// heavyTailRand returns a random value in [0, max) with a heavy tail
// (Pareto-like) so long silences are plausible but short ones are common.
func (b *BurstController) heavyTailRand(max int) int {
	u := b.rng.Float64()
	if u <= 0 {
		u = 0.001
	}
	// Pareto with α=1.5: x = x_min / u^(1/α)
	const alpha = 1.5
	const xMin = 1.0
	x := xMin / math.Pow(u, 1.0/alpha)
	result := int(x * float64(max) / 10) // scale
	if result >= max {
		result = max - 1
	}
	if result < 0 {
		result = 0
	}
	return result
}
