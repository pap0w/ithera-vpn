package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestDeriveObfsParams(t *testing.T) {
	secret := []byte("super-secret-vpn-psk-2026")
	p1, err := DeriveObfsParams(secret)
	if err != nil {
		t.Fatalf("failed to derive params: %v", err)
	}

	// Deterministic
	p2, err := DeriveObfsParams(secret)
	if err != nil {
		t.Fatalf("failed to derive params again: %v", err)
	}

	if p1.MagicInit != p2.MagicInit || p1.MagicResp != p2.MagicResp ||
		p1.MagicCookie != p2.MagicCookie || p1.MagicData != p2.MagicData {
		t.Errorf("derivation is not deterministic: p1 != p2")
	}

	// Must not collide with standard WireGuard IDs (1..4)
	if p1.MagicInit <= 4 || p1.MagicResp <= 4 || p1.MagicCookie <= 4 || p1.MagicData <= 4 {
		t.Errorf("derived magic headers collided with standard WireGuard IDs: %+v", p1)
	}

	// Padding sanity
	if p1.MinPadding <= 0 || p1.MaxPadding <= p1.MinPadding {
		t.Errorf("invalid padding bounds: min=%d, max=%d", p1.MinPadding, p1.MaxPadding)
	}
}

func TestObfuscateAndDeobfuscateType1(t *testing.T) {
	params, _ := DeriveObfsParams([]byte("test-key"))
	codec := NewPacketCodec(params)

	// Create dummy Type 1 packet (148 bytes)
	pkt := make([]byte, Type1InitiationLen)
	_, _ = rand.Read(pkt)
	binary.LittleEndian.PutUint32(pkt[0:4], WgTypeInitiation)

	// Obfuscate
	obfsPkt, ptr, err := codec.Obfuscate(pkt)
	if err != nil {
		t.Fatalf("failed to obfuscate packet: %v", err)
	}
	defer codec.Release(ptr)

	// Verify wire properties
	if len(obfsPkt) == Type1InitiationLen {
		t.Errorf("obfuscated packet should have dynamic padding, got exact 148 bytes")
	}
	magicOnWire := binary.LittleEndian.Uint32(obfsPkt[0:4])
	if magicOnWire != params.MagicInit {
		t.Errorf("expected wire magic %x, got %x", params.MagicInit, magicOnWire)
	}

	// Deobfuscate
	restoredLen, ok := codec.Deobfuscate(obfsPkt)
	if !ok {
		t.Fatalf("deobfuscation failed")
	}
	if restoredLen != Type1InitiationLen {
		t.Fatalf("restored length mismatch: got %d, want %d", restoredLen, Type1InitiationLen)
	}

	// Check restored header
	restoredType := binary.LittleEndian.Uint32(obfsPkt[0:4])
	if restoredType != WgTypeInitiation {
		t.Errorf("restored type mismatch: got %d, want %d", restoredType, WgTypeInitiation)
	}

	// Check payload body matches
	if !bytes.Equal(pkt[4:], obfsPkt[4:restoredLen]) {
		t.Errorf("payload corrupted after deobfuscation")
	}
}

func TestObfuscateAndDeobfuscateType2(t *testing.T) {
	params, _ := DeriveObfsParams([]byte("test-key"))
	codec := NewPacketCodec(params)

	// Create dummy Type 2 packet (92 bytes)
	pkt := make([]byte, Type2ResponseLen)
	_, _ = rand.Read(pkt)
	binary.LittleEndian.PutUint32(pkt[0:4], WgTypeResponse)

	obfsPkt, ptr, err := codec.Obfuscate(pkt)
	if err != nil {
		t.Fatalf("failed to obfuscate packet: %v", err)
	}
	defer codec.Release(ptr)

	if len(obfsPkt) == Type2ResponseLen {
		t.Errorf("obfuscated packet should have dynamic padding, got exact 92 bytes")
	}

	restoredLen, ok := codec.Deobfuscate(obfsPkt)
	if !ok {
		t.Fatalf("deobfuscation failed")
	}
	if restoredLen != Type2ResponseLen {
		t.Fatalf("restored length mismatch: got %d, want %d", restoredLen, Type2ResponseLen)
	}

	restoredType := binary.LittleEndian.Uint32(obfsPkt[0:4])
	if restoredType != WgTypeResponse {
		t.Errorf("restored type mismatch: got %d, want %d", restoredType, WgTypeResponse)
	}
}

func TestObfuscateAndDeobfuscateType4(t *testing.T) {
	params, _ := DeriveObfsParams([]byte("test-key"))
	codec := NewPacketCodec(params)

	// Create dummy Type 4 data packet (100 bytes)
	pkt := make([]byte, 100)
	_, _ = rand.Read(pkt)
	binary.LittleEndian.PutUint32(pkt[0:4], WgTypeData)

	obfsPkt, ptr, err := codec.Obfuscate(pkt)
	if err != nil {
		t.Fatalf("failed to obfuscate packet: %v", err)
	}
	defer codec.Release(ptr)

	magicOnWire := binary.LittleEndian.Uint32(obfsPkt[0:4])
	if magicOnWire != params.MagicData {
		t.Errorf("expected wire magic %x, got %x", params.MagicData, magicOnWire)
	}

	restoredLen, ok := codec.Deobfuscate(obfsPkt)
	if !ok {
		t.Fatalf("deobfuscation failed")
	}
	if restoredLen != 100 {
		t.Fatalf("restored length mismatch: got %d, want 100", restoredLen)
	}

	restoredType := binary.LittleEndian.Uint32(obfsPkt[0:4])
	if restoredType != WgTypeData {
		t.Errorf("restored type mismatch: got %d, want %d", restoredType, WgTypeData)
	}
}

func TestCorruptedPaddingRejected(t *testing.T) {
	params, _ := DeriveObfsParams([]byte("test-key"))
	codec := NewPacketCodec(params)

	pkt := make([]byte, Type1InitiationLen)
	binary.LittleEndian.PutUint32(pkt[0:4], WgTypeInitiation)
	obfsPkt, ptr, _ := codec.Obfuscate(pkt)
	defer codec.Release(ptr)

	// Tamper with the padding trailer
	binary.BigEndian.PutUint16(obfsPkt[len(obfsPkt)-2:len(obfsPkt)], 9999)

	_, ok := codec.Deobfuscate(obfsPkt)
	if ok {
		t.Errorf("expected deobfuscation to fail with invalid padding trailer")
	}
}
