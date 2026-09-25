package core

import (
	"bytes"
	"testing"
	"time"
)

func TestAuthHeaderEncodeDecodeIPv4(t *testing.T) {
	orig := &AuthHeader{
		Version:  Version,
		Command:  CmdTCP,
		AddrType: AddrIPv4,
		Addr:     "1.2.3.4",
		Port:     8080,
	}
	orig.Token = MakeToken("testpassword")

	encoded := orig.Encode()
	decoded, err := DecodeAuthHeader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Version != orig.Version {
		t.Errorf("version: want %d got %d", orig.Version, decoded.Version)
	}
	if decoded.Token != orig.Token {
		t.Errorf("token mismatch")
	}
	if decoded.Command != orig.Command {
		t.Errorf("command: want %d got %d", orig.Command, decoded.Command)
	}
	if decoded.Addr != orig.Addr {
		t.Errorf("addr: want %s got %s", orig.Addr, decoded.Addr)
	}
	if decoded.Port != orig.Port {
		t.Errorf("port: want %d got %d", orig.Port, decoded.Port)
	}
}

func TestAuthHeaderEncodeDecodeHostname(t *testing.T) {
	orig := &AuthHeader{
		Version:  Version,
		Command:  CmdTCP,
		AddrType: AddrHostname,
		Addr:     "example.com",
		Port:     443,
	}
	orig.Token = MakeToken("testpassword")

	encoded := orig.Encode()
	decoded, err := DecodeAuthHeader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Addr != "example.com" {
		t.Errorf("hostname: want example.com got %s", decoded.Addr)
	}
	if decoded.Port != 443 {
		t.Errorf("port: want 443 got %d", decoded.Port)
	}
}

func TestAuthHeaderEncodeDecodeIPv6(t *testing.T) {
	orig := &AuthHeader{
		Version:  Version,
		Command:  CmdUDP,
		AddrType: AddrIPv6,
		Addr:     "2001:db8::1",
		Port:     53,
	}
	orig.Token = MakeToken("pw")

	encoded := orig.Encode()
	decoded, err := DecodeAuthHeader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode IPv6: %v", err)
	}
	if decoded.Command != CmdUDP {
		t.Errorf("command: want UDP got %d", decoded.Command)
	}
}

func TestMakeTokenUnique(t *testing.T) {
	t1 := MakeToken("password")
	t2 := MakeToken("password")
	if t1 == t2 {
		t.Error("tokens must carry a fresh nonce so reconnects are not seen as replays")
	}
	if !ValidateToken(t1, "password") || !ValidateToken(t2, "password") {
		t.Error("both tokens made in the same window must validate")
	}
}

func TestValidateTokenNextWindow(t *testing.T) {
	now := time.Now().Unix() / 30
	next := tokenForBucket("pw", now+1)
	if !ValidateToken(next, "pw") {
		t.Error("next bucket token must validate (client clock slightly ahead)")
	}
}

func TestValidateTokenTampered(t *testing.T) {
	tok := MakeToken("pw")
	tok[0] ^= 0xff // nonce no longer matches the MAC
	if ValidateToken(tok, "pw") {
		t.Error("token with modified nonce must be rejected")
	}
}

func TestValidateTokenCurrentWindow(t *testing.T) {
	token := MakeToken("mypassword")
	if !ValidateToken(token, "mypassword") {
		t.Error("current window token must validate")
	}
}

func TestValidateTokenWrongPassword(t *testing.T) {
	token := MakeToken("rightpassword")
	if ValidateToken(token, "wrongpassword") {
		t.Error("token for wrong password must not validate")
	}
}

func TestValidateTokenPreviousWindow(t *testing.T) {
	// Simulate a token from the previous bucket
	now := time.Now().Unix() / 30
	prev := tokenForBucket("pw", now-1)
	if !ValidateToken(prev, "pw") {
		t.Error("previous bucket token must validate (clock skew tolerance)")
	}
}

func TestValidateTokenOldWindow(t *testing.T) {
	// Token from 2 buckets ago must NOT validate
	now := time.Now().Unix() / 30
	old := tokenForBucket("pw", now-2)
	if ValidateToken(old, "pw") {
		t.Error("token from 2 buckets ago must be rejected")
	}
}

func TestVersionMismatch(t *testing.T) {
	bad := []byte{0x99} // wrong version
	_, err := DecodeAuthHeader(bytes.NewReader(bad))
	if err == nil {
		t.Error("expected error for version mismatch")
	}
}

func TestTargetAddrIPv6(t *testing.T) {
	h := &AuthHeader{Addr: "2001:db8::1", Port: 443}
	if got := h.TargetAddr(); got != "[2001:db8::1]:443" {
		t.Errorf("TargetAddr: want [2001:db8::1]:443 got %s", got)
	}
}

func TestUDPDatagramRoundTrip(t *testing.T) {
	payload := []byte("dns-query")
	for _, tc := range []struct {
		t    AddrType
		addr string
	}{{AddrIPv4, "10.1.2.3"}, {AddrIPv6, "2001:db8::2"}, {AddrHostname, "example.com"}} {
		b := EncodeUDPDatagram(7, tc.t, tc.addr, 53, payload)
		d, err := DecodeUDPDatagram(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.addr, err)
		}
		if d.Session != 7 || d.AddrType != tc.t || d.Addr != tc.addr || d.Port != 53 || !bytes.Equal(d.Payload, payload) {
			t.Errorf("%s: round trip mismatch: %+v", tc.addr, d)
		}
	}
}

func TestPaddedFlag(t *testing.T) {
	h := &AuthHeader{Command: CmdTCP | CmdFlagPadded}
	if h.Cmd() != CmdTCP || !h.Padded() {
		t.Errorf("flag decode: cmd=%d padded=%v", h.Cmd(), h.Padded())
	}
}

func TestTargetAddr(t *testing.T) {
	h := &AuthHeader{Addr: "example.com", Port: 443}
	if got := h.TargetAddr(); got != "example.com:443" {
		t.Errorf("TargetAddr: want example.com:443 got %s", got)
	}
}
