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

func TestMakeTokenConsistency(t *testing.T) {
	t1 := MakeToken("password")
	t2 := MakeToken("password")
	if t1 != t2 {
		t.Error("tokens made in the same 30s window must match")
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

func TestTargetAddr(t *testing.T) {
	h := &AuthHeader{Addr: "example.com", Port: 443}
	if got := h.TargetAddr(); got != "example.com:443" {
		t.Errorf("TargetAddr: want example.com:443 got %s", got)
	}
}
