package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// KeyLen defines the length in bytes of Curve25519 keys (32 bytes).
const KeyLen = 32

// GeneratePrivateKey generates a secure random 32-byte Curve25519 private key.
func GeneratePrivateKey() ([KeyLen]byte, error) {
	var key [KeyLen]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("crypto/rand error: %w", err)
	}
	// Curve25519 clamping
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return key, nil
}

// PublicKey derives the 32-byte public key from a Curve25519 private key.
func PublicKey(privateKey [KeyLen]byte) ([KeyLen]byte, error) {
	var pub [KeyLen]byte
	res, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("failed to derive public key: %w", err)
	}
	copy(pub[:], res)
	return pub, nil
}

// KeyToBase64 encodes a 32-byte key to standard Base64 string.
func KeyToBase64(key [KeyLen]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// KeyToHex encodes a 32-byte key to standard lower-case hexadecimal string.
func KeyToHex(key [KeyLen]byte) string {
	return hex.EncodeToString(key[:])
}

// ParseKey parses a key string that may be formatted either as Base64 (44 chars) or Hex (64 chars).
func ParseKey(input string) ([KeyLen]byte, error) {
	var key [KeyLen]byte
	trimmed := strings.TrimSpace(input)

	if len(trimmed) == 64 {
		b, err := hex.DecodeString(trimmed)
		if err != nil {
			return key, fmt.Errorf("invalid hex key: %w", err)
		}
		if len(b) != KeyLen {
			return key, errors.New("hex key length mismatch")
		}
		copy(key[:], b)
		return key, nil
	}

	b, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return key, fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(b) != KeyLen {
		return key, fmt.Errorf("key byte length must be 32, got %d", len(b))
	}
	copy(key[:], b)
	return key, nil
}

// ConstantTimeCompare compares two byte slices in constant time to prevent timing attacks.
func ConstantTimeCompare(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}
