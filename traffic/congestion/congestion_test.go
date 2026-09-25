package congestion

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func testTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"mirage-cc-test"},
	}
	client = &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{"mirage-cc-test"}}
	return server, client
}

// transferWithCC sends size bytes from a server connection to a client over
// loopback QUIC. install is called on the server connection before sending.
// It returns once the server connection's run loop has exited, so the
// installed controller can be inspected without racing quic-go.
func transferWithCC(t *testing.T, size int, install func(*quic.Conn) quic.CongestionControl) quic.CongestionControl {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.Listen(udp, serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		cc   quic.CongestionControl
		conn *quic.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		cc := install(conn)
		str, err := conn.OpenUniStream()
		if err == nil {
			_, err = str.Write(make([]byte, size))
		}
		if err == nil {
			err = str.Close()
		}
		done <- result{cc: cc, conn: conn, err: err}
	}()

	client, err := quic.DialAddr(ctx, ln.Addr().String(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	str, err := client.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, str)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(size) {
		t.Fatalf("received %d bytes, want %d", n, size)
	}

	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	client.CloseWithError(0, "")
	select {
	case <-res.conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("server connection did not close")
	}
	return res.cc
}

func TestUseBBRInstallsController(t *testing.T) {
	const size = 1 << 20
	cc := transferWithCC(t, size, func(conn *quic.Conn) quic.CongestionControl {
		return installBBR(conn, nil)
	})

	bbr := cc.(*bbrSender)
	// quic-go must have driven the controller: without the hook, none of this state moves.
	if bbr.lastSentPacket == 0 || bbr.lastSentTime.IsZero() {
		t.Fatal("BBR OnPacketSent was never called: controller not installed")
	}
	if bbr.maxBandwidth.get() == 0 || bbr.minRTT == math.MaxInt64 {
		t.Fatal("BBR OnPacketAcked was never called: controller not installed")
	}
	if bbr.datagramSize == 0 {
		t.Fatal("SetMaxDatagramSize was never called")
	}
}

func TestUseJitteredBBRInstallsController(t *testing.T) {
	const size = 1 << 20
	cc := transferWithCC(t, size, func(conn *quic.Conn) quic.CongestionControl {
		return installBBR(conn, &JitterConfig{Fraction: 0.15, Smoothing: 0.3})
	})

	j := cc.(*jitterWrapper)
	bbr := j.inner.(*bbrSender)
	if bbr.lastSentPacket == 0 || bbr.maxBandwidth.get() == 0 {
		t.Fatal("jittered BBR was never driven by quic-go: controller not installed")
	}
	if j.lastStep.IsZero() {
		t.Fatal("jitter EMA was never stepped by ACKs")
	}
}

// The public entry points used by core/server.go must not panic and must hand a
// controller to quic-go (covered in detail by the tests above via installBBR).
func TestUseBBRPublicAPI(t *testing.T) {
	transferWithCC(t, 64<<10, func(conn *quic.Conn) quic.CongestionControl {
		UseBBR(conn)
		return nil
	})
	transferWithCC(t, 64<<10, func(conn *quic.Conn) quic.CongestionControl {
		UseJitteredBBR(conn, DefaultJitterConfig)
		return nil
	})
}

func TestJitterAffectsCanSend(t *testing.T) {
	inner := newBBRSender(maxDatagramSize)
	j := newJitterWrapper(inner, JitterConfig{Fraction: 0.2, Smoothing: 0.5})

	base := inner.GetCongestionWindow()
	j.currentJitter = -0.2 // window shrunk by 20%
	justBelowBase := base - 1
	if !inner.CanSend(justBelowBase) {
		t.Fatal("precondition: inner BBR allows sending just below its window")
	}
	if j.CanSend(justBelowBase) {
		t.Fatal("jittered window (-20%) should block sending at the unjittered window")
	}

	j.currentJitter = 0.2 // window grown by 20%
	if !j.CanSend(base) {
		t.Fatal("jittered window (+20%) should allow sending beyond the unjittered window")
	}
}

func TestJitterStepsOnAckClock(t *testing.T) {
	inner := newBBRSender(maxDatagramSize)
	j := newJitterWrapper(inner, DefaultJitterConfig)

	now := time.Now()
	j.OnPacketAcked(1, maxDatagramSize, 0, now)
	first := j.currentJitter
	// an ACK within the step interval must not move the EMA
	j.OnPacketAcked(2, maxDatagramSize, 0, now.Add(jitterStepInterval/2))
	if j.currentJitter != first {
		t.Fatal("jitter stepped more than once within jitterStepInterval")
	}
	if !j.lastStep.Equal(now) {
		t.Fatal("jitter step time not recorded")
	}
}
