package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/HaizakiKu/mirage/config"
)

// startClient runs a real Client (SOCKS5 → shaper → uTLS QUIC) against env and
// returns it together with its SOCKS5 address.
func startClient(t *testing.T, env *testEnv, profile string) (*Client, string) {
	t.Helper()
	c, err := NewClient(&config.ClientConfig{
		Server:   env.serverAddr,
		Password: testPassword,
		Traffic:  config.TrafficConfig{Profile: profile},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.rootCAs = env.certPool

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("SOCKS5 listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.serve(ctx, ln) //nolint:errcheck
	return c, ln.Addr().String()
}

// socksRequest performs the SOCKS5 greeting and sends a request, returning the
// reply code and bound address.
func socksRequest(t *testing.T, conn net.Conn, cmd byte, target string) (byte, *net.UDPAddr) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	defer conn.SetDeadline(time.Time{})                //nolint:errcheck

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil || sel != [2]byte{5, 0} {
		t.Fatalf("method selection: %v %v", sel, err)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	var port uint16
	fmt.Sscan(portStr, &port) //nolint:errcheck
	typ, addr := addrTypeFor(host)
	req := appendAddr([]byte{5, cmd, 0}, typ, addr, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("request: %v", err)
	}

	var hdr [3]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("reply: %v", err)
	}
	rt, raddr, rport, err := readAddr(conn)
	if err != nil {
		t.Fatalf("reply addr: %v", err)
	}
	_ = rt
	return hdr[1], &net.UDPAddr{IP: net.ParseIP(raddr), Port: int(rport)}
}

func socksConnect(t *testing.T, socksAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	if rep, _ := socksRequest(t, conn, socks5CmdConnect, target); rep != socks5RepSuccess {
		conn.Close()
		t.Fatalf("CONNECT reply: 0x%02x", rep)
	}
	return conn
}

func checkEcho(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	msg := make([]byte, size)
	rand.Read(msg)                                     //nolint:errcheck
	conn.SetDeadline(time.Now().Add(20 * time.Second)) //nolint:errcheck
	go conn.Write(msg)                                 //nolint:errcheck
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo data corrupted through the proxy")
	}
}

// TestClientConnectShaped: full client path with padding + burst shaping must
// deliver data byte-exact.
func TestClientConnectShaped(t *testing.T) {
	echoAddr := startEchoServer(t)
	env := newTestEnv(t, 0)
	_, socksAddr := startClient(t, env, "browse")

	conn := socksConnect(t, socksAddr, echoAddr)
	defer conn.Close()
	checkEcho(t, conn, 13)
	checkEcho(t, conn, 200*1024)
}

func TestClientConnectUnshaped(t *testing.T) {
	echoAddr := startEchoServer(t)
	env := newTestEnv(t, 0)
	_, socksAddr := startClient(t, env, "")

	conn := socksConnect(t, socksAddr, echoAddr)
	defer conn.Close()
	checkEcho(t, conn, 64*1024)
}

// TestClientReconnectSameWindow: a new QUIC connection within the same 30s
// window must authenticate (tokens are unique, not per-window).
func TestClientReconnectSameWindow(t *testing.T) {
	echoAddr := startEchoServer(t)
	env := newTestEnv(t, 0)
	c, socksAddr := startClient(t, env, "browse")

	conn := socksConnect(t, socksAddr, echoAddr)
	checkEcho(t, conn, 100)
	conn.Close()

	c.mu.Lock()
	c.conn.CloseWithError(0, "force reconnect") //nolint:errcheck
	c.mu.Unlock()

	conn = socksConnect(t, socksAddr, echoAddr)
	defer conn.Close()
	checkEcho(t, conn, 100)

	// A second, independent client in the same window as well.
	_, socksAddr2 := startClient(t, env, "browse")
	conn2 := socksConnect(t, socksAddr2, echoAddr)
	defer conn2.Close()
	checkEcho(t, conn2, 100)
}

// TestClientHalfClose: the app closes its write side after the request; the
// response must still arrive in full.
func TestClientHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c) // until the client's FIN
		fmt.Fprintf(c, "received %d bytes", n)
	}()

	env := newTestEnv(t, 0)
	_, socksAddr := startClient(t, env, "browse")
	conn := socksConnect(t, socksAddr, ln.Addr().String())
	defer conn.Close()

	conn.Write(bytes.Repeat([]byte("a"), 5000))        //nolint:errcheck
	conn.(*net.TCPConn).CloseWrite()                   //nolint:errcheck
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(resp) != "received 5000 bytes" {
		t.Fatalf("response: %q", resp)
	}
}

func TestClientConnectIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	env := newTestEnv(t, 0)
	_, socksAddr := startClient(t, env, "browse")
	conn := socksConnect(t, socksAddr, ln.Addr().String())
	defer conn.Close()
	checkEcho(t, conn, 1000)
}

func TestClientBindNotSupported(t *testing.T) {
	env := newTestEnv(t, 0)
	_, socksAddr := startClient(t, env, "browse")
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if rep, _ := socksRequest(t, conn, 0x02, "127.0.0.1:80"); rep != socks5RepCmdNotSupported {
		t.Fatalf("BIND reply: want 0x07 got 0x%02x", rep)
	}
}

// TestClientUDPAssociate: SOCKS5 UDP ASSOCIATE relays datagrams through the server.
func TestClientUDPAssociate(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], from) //nolint:errcheck
		}
	}()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	env := newTestEnv(t, 0)
	_, socksAddr := startClient(t, env, "browse")

	ctrl, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	rep, relayAddr := socksRequest(t, ctrl, socks5CmdUDP, "0.0.0.0:0")
	if rep != socks5RepSuccess {
		t.Fatalf("UDP ASSOCIATE reply: 0x%02x", rep)
	}

	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("udp-packet-%d", i))
		pkt := appendAddr([]byte{0, 0, 0}, AddrIPv4, "127.0.0.1", uint16(echoAddr.Port))
		if _, err := app.WriteToUDP(append(pkt, payload...), relayAddr); err != nil {
			t.Fatalf("send: %v", err)
		}

		app.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		buf := make([]byte, 2048)
		n, err := app.Read(buf)
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if n < 3 || buf[2] != 0 {
			t.Fatalf("bad SOCKS UDP header")
		}
		r := &sliceReader{b: buf[3:n]}
		_, from, port, err := readAddr(r)
		if err != nil {
			t.Fatalf("reply addr: %v", err)
		}
		if from != "127.0.0.1" || int(port) != echoAddr.Port {
			t.Errorf("reply source: %s:%d", from, port)
		}
		if !bytes.Equal(r.b, payload) {
			t.Errorf("payload: want %q got %q", payload, r.b)
		}
	}
}

// TestUTLSWithECH: the production uTLS client must complete an ECH handshake.
func TestUTLSWithECH(t *testing.T) {
	env := newTestEnv(t, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	echList, err := ParseECHConfigList(base64.StdEncoding.EncodeToString(env.echConfigList))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := ClientTLSConfig("localhost", echList)
	tlsCfg.RootCAs = env.certPool
	conn, err := NewQUICClient(ctx, env.serverAddr, tlsCfg)
	if err != nil {
		t.Fatalf("uTLS + ECH dial: %v", err)
	}
	defer conn.CloseWithError(0, "done") //nolint:errcheck
	if !conn.ConnectionState().TLS.ECHAccepted {
		t.Error("ECH not accepted with uTLS client")
	}
}

// TestAuthPartialHeader: a peer that sends an incomplete header must not stall
// the handler; it is routed to the masquerade after the auth timeout.
func TestAuthPartialHeader(t *testing.T) {
	const shortTimeout = 200 * time.Millisecond
	env, mock := newTestEnvWithMock(t, shortTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn := env.dialServer(ctx)
	defer conn.CloseWithError(0, "done") //nolint:errcheck

	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte{Version, 1, 2, 3}) //nolint:errcheck

	select {
	case <-mock.called:
	case <-time.After(shortTimeout + time.Second):
		t.Error("partial header stalled the server instead of falling back to masquerade")
	}
}
