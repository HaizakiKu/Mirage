package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const Version = 0x01

type Command uint8

const (
	CmdTCP Command = 0x01
	CmdUDP Command = 0x02
)

type AddrType uint8

const (
	AddrIPv4     AddrType = 0x01
	AddrHostname AddrType = 0x03
	AddrIPv6     AddrType = 0x04
)

// AuthHeader is the first frame sent by the client on a new QUIC stream
type AuthHeader struct {
	Version  uint8
	Token    [32]byte
	Command  Command
	AddrType AddrType
	Addr     string
	Port     uint16
}

// Encode serializes the AuthHeader to bytes
func (h *AuthHeader) Encode() []byte {
	var buf []byte
	buf = append(buf, h.Version)
	buf = append(buf, h.Token[:]...)
	buf = append(buf, byte(h.Command))
	buf = append(buf, byte(h.AddrType))

	switch h.AddrType {
	case AddrIPv4:
		ip := net.ParseIP(h.Addr).To4()
		buf = append(buf, ip...)
	case AddrIPv6:
		ip := net.ParseIP(h.Addr).To16()
		buf = append(buf, ip...)
	case AddrHostname:
		name := []byte(h.Addr)
		buf = append(buf, byte(len(name)))
		buf = append(buf, name...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, h.Port)
	buf = append(buf, portBytes...)

	return buf
}

// DecodeAuthHeader parses bytes from a reader into an AuthHeader
func DecodeAuthHeader(r io.Reader) (*AuthHeader, error) {
	h := &AuthHeader{}

	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	h.Version = ver[0]
	if h.Version != Version {
		return nil, fmt.Errorf("unsupported version: 0x%02x", h.Version)
	}

	if _, err := io.ReadFull(r, h.Token[:]); err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}

	var cmdAddr [2]byte
	if _, err := io.ReadFull(r, cmdAddr[:]); err != nil {
		return nil, fmt.Errorf("read command/addrtype: %w", err)
	}
	h.Command = Command(cmdAddr[0])
	h.AddrType = AddrType(cmdAddr[1])

	switch h.AddrType {
	case AddrIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, fmt.Errorf("read ipv4: %w", err)
		}
		h.Addr = net.IP(ip).String()
	case AddrIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return nil, fmt.Errorf("read ipv6: %w", err)
		}
		h.Addr = net.IP(ip).String()
	case AddrHostname:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return nil, fmt.Errorf("read hostname len: %w", err)
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, fmt.Errorf("read hostname: %w", err)
		}
		h.Addr = string(name)
	default:
		return nil, fmt.Errorf("unknown addr type: 0x%02x", h.AddrType)
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	h.Port = binary.BigEndian.Uint16(portBytes[:])

	return h, nil
}

// MakeToken generates an HMAC-SHA256 auth token for the current 30-second window
func MakeToken(password string) [32]byte {
	ts := time.Now().Unix() / 30
	return tokenForBucket(password, ts)
}

// ValidateToken checks if the token matches the current or previous 30-second window
func ValidateToken(token [32]byte, password string) bool {
	now := time.Now().Unix() / 30
	if token == tokenForBucket(password, now) {
		return true
	}
	if token == tokenForBucket(password, now-1) {
		return true
	}
	return false
}

func tokenForBucket(password string, bucket int64) [32]byte {
	mac := hmac.New(sha256.New, []byte(password))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	mac.Write(b[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// TargetAddr returns "host:port" string from the header
func (h *AuthHeader) TargetAddr() string {
	return fmt.Sprintf("%s:%d", h.Addr, h.Port)
}

// ErrInvalidToken is returned when the auth token fails validation
var ErrInvalidToken = errors.New("invalid auth token")
