package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const Version = 0x01

type Command uint8

const (
	CmdTCP Command = 0x01
	CmdUDP Command = 0x02

	// CmdFlagPadded is OR-ed into the command byte when the client wraps the
	// client→server data that follows the header in padding frames
	// (see traffic.PaddedReader). The low 7 bits carry the command itself.
	CmdFlagPadded Command = 0x80
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

// Cmd returns the command without flag bits.
func (h *AuthHeader) Cmd() Command { return h.Command &^ CmdFlagPadded }

// Padded reports whether the data following the header is padding-framed.
func (h *AuthHeader) Padded() bool { return h.Command&CmdFlagPadded != 0 }

// Encode serializes the AuthHeader to bytes
func (h *AuthHeader) Encode() []byte {
	var buf []byte
	buf = append(buf, h.Version)
	buf = append(buf, h.Token[:]...)
	buf = append(buf, byte(h.Command))
	buf = appendAddr(buf, h.AddrType, h.Addr, h.Port)
	return buf
}

// appendAddr appends [addrType][addr][port] to buf.
func appendAddr(buf []byte, t AddrType, addr string, port uint16) []byte {
	buf = append(buf, byte(t))
	switch t {
	case AddrIPv4:
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			ip = net.IPv4zero.To4()
		}
		buf = append(buf, ip...)
	case AddrIPv6:
		ip := net.ParseIP(addr).To16()
		if ip == nil {
			ip = net.IPv6zero
		}
		buf = append(buf, ip...)
	case AddrHostname:
		name := []byte(addr)
		if len(name) > 255 {
			name = name[:255]
		}
		buf = append(buf, byte(len(name)))
		buf = append(buf, name...)
	}
	return binary.BigEndian.AppendUint16(buf, port)
}

// readAddr parses [addrType][addr][port] from r.
func readAddr(r io.Reader) (AddrType, string, uint16, error) {
	var tb [1]byte
	if _, err := io.ReadFull(r, tb[:]); err != nil {
		return 0, "", 0, fmt.Errorf("read addrtype: %w", err)
	}
	t := AddrType(tb[0])

	var addr string
	switch t {
	case AddrIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", 0, fmt.Errorf("read ipv4: %w", err)
		}
		addr = net.IP(ip).String()
	case AddrIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", 0, fmt.Errorf("read ipv6: %w", err)
		}
		addr = net.IP(ip).String()
	case AddrHostname:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return 0, "", 0, fmt.Errorf("read hostname len: %w", err)
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return 0, "", 0, fmt.Errorf("read hostname: %w", err)
		}
		addr = string(name)
	default:
		return 0, "", 0, fmt.Errorf("unknown addr type: 0x%02x", t)
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return 0, "", 0, fmt.Errorf("read port: %w", err)
	}
	return t, addr, binary.BigEndian.Uint16(portBytes[:]), nil
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

	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return nil, fmt.Errorf("read command: %w", err)
	}
	h.Command = Command(cmd[0])

	t, addr, port, err := readAddr(r)
	if err != nil {
		return nil, err
	}
	h.AddrType, h.Addr, h.Port = t, addr, port
	return h, nil
}

// Auth token layout: nonce(16) || HMAC-SHA256(password, bucket || nonce)[:16].
// The random nonce makes every token unique, so the server's replay cache can
// reject reuse without also rejecting a legitimate reconnect in the same window.
const (
	tokenNonceLen = 16
	tokenWindow   = 30 // seconds per time bucket
)

// MakeToken generates a fresh auth token bound to the current 30-second window
func MakeToken(password string) [32]byte {
	return tokenForBucket(password, time.Now().Unix()/tokenWindow)
}

// ValidateToken checks the token against the previous, current and next
// 30-second windows (the next one tolerates a client clock slightly ahead).
func ValidateToken(token [32]byte, password string) bool {
	now := time.Now().Unix() / tokenWindow
	nonce := token[:tokenNonceLen]
	for _, b := range []int64{now - 1, now, now + 1} {
		mac := tokenMAC(password, b, nonce)
		if hmac.Equal(token[tokenNonceLen:], mac[:len(token)-tokenNonceLen]) {
			return true
		}
	}
	return false
}

func tokenForBucket(password string, bucket int64) [32]byte {
	var out [32]byte
	if _, err := rand.Read(out[:tokenNonceLen]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	mac := tokenMAC(password, bucket, out[:tokenNonceLen])
	copy(out[tokenNonceLen:], mac)
	return out
}

func tokenMAC(password string, bucket int64, nonce []byte) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	mac.Write(b[:])
	mac.Write(nonce)
	return mac.Sum(nil)
}

// TargetAddr returns "host:port" string from the header (IPv6 hosts are bracketed)
func (h *AuthHeader) TargetAddr() string {
	return net.JoinHostPort(h.Addr, strconv.Itoa(int(h.Port)))
}

// ErrInvalidToken is returned when the auth token fails validation
var ErrInvalidToken = errors.New("invalid auth token")

// --- UDP datagrams ---
//
// Each QUIC datagram carries one UDP packet:
//   [4B session ID][addrType][addr][port][payload]
// The session ID is the QUIC stream ID of the CmdUDP control stream that
// opened the association. Client→server the address is the destination;
// server→client it is the source of the reply.

// EncodeUDPDatagram builds a datagram for the given session and address.
func EncodeUDPDatagram(session uint32, t AddrType, addr string, port uint16, payload []byte) []byte {
	buf := make([]byte, 4, 4+1+1+255+2+len(payload))
	binary.BigEndian.PutUint32(buf, session)
	buf = appendAddr(buf, t, addr, port)
	return append(buf, payload...)
}

// UDPDatagram is a decoded UDP relay datagram.
type UDPDatagram struct {
	Session  uint32
	AddrType AddrType
	Addr     string
	Port     uint16
	Payload  []byte
}

// DecodeUDPDatagram parses a datagram produced by EncodeUDPDatagram.
func DecodeUDPDatagram(b []byte) (*UDPDatagram, error) {
	if len(b) < 4 {
		return nil, errors.New("udp datagram too short")
	}
	d := &UDPDatagram{Session: binary.BigEndian.Uint32(b)}
	r := &sliceReader{b: b[4:]}
	t, addr, port, err := readAddr(r)
	if err != nil {
		return nil, err
	}
	d.AddrType, d.Addr, d.Port, d.Payload = t, addr, port, r.b
	return d, nil
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

// addrTypeFor classifies a host string for the wire format.
func addrTypeFor(host string) (AddrType, string) {
	ip := net.ParseIP(host)
	if ip == nil {
		return AddrHostname, host
	}
	if ip4 := ip.To4(); ip4 != nil {
		return AddrIPv4, ip4.String()
	}
	return AddrIPv6, ip.String()
}
