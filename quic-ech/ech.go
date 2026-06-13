// Package ech provides ECH (Encrypted Client Hello) key management for Mirage.
// Wraps Go 1.24 standard library ECH support with key generation and persistence.
package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"os"
)

// Provider manages ECH keys for a TLS server.
type Provider struct {
	keys []tls.EncryptedClientHelloKey
}

// NewProvider loads ECH keys from keyFile, or generates them if the file is absent.
// publicName is the outer SNI used in ECH (e.g. "cloudflare.com").
func NewProvider(publicName string, keyFile string) (*Provider, error) {
	if keyFile != "" {
		if keys, err := loadKeys(keyFile); err == nil {
			return &Provider{keys: keys}, nil
		}
	}

	key, err := generateKey(publicName)
	if err != nil {
		return nil, err
	}

	if keyFile != "" {
		_ = saveKey(keyFile, key)
	}

	return &Provider{keys: []tls.EncryptedClientHelloKey{key}}, nil
}

// Keys returns the ECH keys for use in tls.Config.EncryptedClientHelloKeys.
// Each key's Config field is a single ECHConfig (not a list), as required by
// Go 1.24's crypto/tls which calls parseECHConfig (not parseECHConfigList) on it.
func (p *Provider) Keys() []tls.EncryptedClientHelloKey {
	return p.keys
}

// ConfigList returns an ECHConfigList to be distributed to clients via DNS HTTPS
// records and used as tls.Config.EncryptedClientHelloConfigList.
// Wraps the single ECHConfig in a uint16-length-prefixed list as required by
// Go's parseECHConfigList and draft-ietf-tls-esni-18.
func (p *Provider) ConfigList() []byte {
	if len(p.keys) == 0 {
		return nil
	}
	cfg := p.keys[0].Config // single ECHConfig bytes
	list := make([]byte, 2+len(cfg))
	list[0] = byte(len(cfg) >> 8)
	list[1] = byte(len(cfg))
	copy(list[2:], cfg)
	return list
}

func generateKey(publicName string) (tls.EncryptedClientHelloKey, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}

	echCfg, err := buildECHConfig(publicName, privKey.PublicKey().Bytes())
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}

	// Config must be a single ECHConfig (not a list).
	// PrivateKey must be ecdh.PrivateKey.Bytes() — raw 32-byte X25519 key.
	return tls.EncryptedClientHelloKey{
		Config:      echCfg,
		PrivateKey:  privKey.Bytes(),
		SendAsRetry: true,
	}, nil
}

// buildECHConfig constructs a single ECHConfig wire encoding per
// draft-ietf-tls-esni-18.  HPKE identifiers follow RFC 9180:
//
//	kem_id  0x0020 = DHKEM(X25519, HKDF-SHA256)
//	kdf_id  0x0001 = HKDF-SHA256
//	aead_id 0x0001 = AES-128-GCM
//
// The returned bytes are: version(uint16=0xfe0d) + length(uint16) + ECHConfigContents.
// This is what Go 1.24 expects in EncryptedClientHelloKey.Config.
func buildECHConfig(publicName string, pubKeyBytes []byte) ([]byte, error) {
	nameBytes := []byte(publicName)
	if len(nameBytes) == 0 || len(nameBytes) > 255 {
		return nil, errors.New("ech: public_name must be 1-255 bytes")
	}

	// --- ECHConfigContents ---
	var contents []byte

	// key_config.config_id (uint8)
	contents = append(contents, 0x01)

	// key_config.kem_id (uint16) = DHKEM(X25519, HKDF-SHA256) = 0x0020
	contents = append(contents, 0x00, 0x20)

	// key_config.public_key (uint16 len + 32 bytes)
	pubLen := len(pubKeyBytes)
	contents = append(contents, uint8(pubLen>>8), uint8(pubLen))
	contents = append(contents, pubKeyBytes...)

	// key_config.cipher_suites (uint16 total_len + suites)
	// One suite: kdf_id=0x0001 (HKDF-SHA256) + aead_id=0x0001 (AES-128-GCM) = 4 bytes
	contents = append(contents, 0x00, 0x04)
	contents = append(contents, 0x00, 0x01) // kdf_id: HKDF-SHA256
	contents = append(contents, 0x00, 0x01) // aead_id: AES-128-GCM

	// maximum_name_length (uint8): 0 = no limit
	contents = append(contents, 0x00)

	// public_name (uint8 len + bytes)
	contents = append(contents, uint8(len(nameBytes)))
	contents = append(contents, nameBytes...)

	// extensions (uint16 len = 0, no extensions)
	contents = append(contents, 0x00, 0x00)

	// --- ECHConfig ---
	// version(uint16=0xfe0d) + length(uint16) + ECHConfigContents
	echConfig := []byte{0xfe, 0x0d}
	cLen := len(contents)
	echConfig = append(echConfig, uint8(cLen>>8), uint8(cLen))
	echConfig = append(echConfig, contents...)

	return echConfig, nil
}

// --- persistence (PEM-based) ---

func loadKeys(path string) ([]tls.EncryptedClientHelloKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var configBytes, privBytes []byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "ECH CONFIG":
			configBytes = block.Bytes
		case "ECH PRIVATE KEY":
			privBytes = block.Bytes
		}
		data = rest
	}

	if len(configBytes) == 0 || len(privBytes) == 0 {
		return nil, errors.New("ech: incomplete key file")
	}

	return []tls.EncryptedClientHelloKey{{
		Config:      configBytes,
		PrivateKey:  privBytes,
		SendAsRetry: true,
	}}, nil
}

func saveKey(path string, key tls.EncryptedClientHelloKey) error {
	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{
		Type:  "ECH CONFIG",
		Bytes: key.Config,
	})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{
		Type:  "ECH PRIVATE KEY",
		Bytes: key.PrivateKey,
	})...)
	return os.WriteFile(path, out, 0600)
}
