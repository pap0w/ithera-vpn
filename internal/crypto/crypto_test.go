package crypto

import (
	"testing"
)

func TestKeyPairGenerationAndEncoding(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	pub, err := PublicKey(priv)
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	// Verify Base64 roundtrip
	privB64 := KeyToBase64(priv)
	parsedPriv, err := ParseKey(privB64)
	if err != nil {
		t.Fatalf("ParseKey from base64 failed: %v", err)
	}
	if parsedPriv != priv {
		t.Fatalf("Parsed private key mismatch from base64")
	}

	// Verify Hex roundtrip
	pubHex := KeyToHex(pub)
	parsedPub, err := ParseKey(pubHex)
	if err != nil {
		t.Fatalf("ParseKey from hex failed: %v", err)
	}
	if parsedPub != pub {
		t.Fatalf("Parsed public key mismatch from hex")
	}

	// Verify constant time compare
	if !ConstantTimeCompare(pub[:], parsedPub[:]) {
		t.Fatalf("ConstantTimeCompare returned false for identical keys")
	}
}

func TestParseKeyInvalid(t *testing.T) {
	_, err := ParseKey("invalid-short-key")
	if err == nil {
		t.Fatalf("expected error on invalid key string, got nil")
	}
}
