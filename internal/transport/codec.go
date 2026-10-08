package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	// WireGuard standard packet lengths
	Type1InitiationLen = 148
	Type2ResponseLen   = 92
	Type3CookieLen     = 64
	Type4MinDataLen    = 32

	// WireGuard standard message type IDs
	WgTypeInitiation uint32 = 1
	WgTypeResponse   uint32 = 2
	WgTypeCookie     uint32 = 3
	WgTypeData       uint32 = 4

	// Default padding bounds
	DefaultMinPadding = 24
	DefaultMaxPadding = 64
)

// ObfsParams holds derived anti-DPI obfuscation parameters.
type ObfsParams struct {
	MagicInit   uint32
	MagicResp   uint32
	MagicCookie uint32
	MagicData   uint32
	MinPadding  int
	MaxPadding  int
}

// DeriveObfsParams derives pseudorandom magic headers and padding ranges from a shared secret via HKDF-SHA256.
func DeriveObfsParams(secret []byte) (ObfsParams, error) {
	if len(secret) == 0 {
		return ObfsParams{}, errors.New("obfs secret cannot be empty")
	}

	salt := []byte("ithera-anti-dpi-salt-v1")
	info := []byte("ithera-wireguard-obfs-derivation")
	h := hkdf.New(sha256.New, secret, salt, info)

	var derived [20]byte
	if _, err := io.ReadFull(h, derived[:]); err != nil {
		return ObfsParams{}, fmt.Errorf("hkdf expansion failed: %w", err)
	}

	p := ObfsParams{
		MagicInit:   binary.LittleEndian.Uint32(derived[0:4]),
		MagicResp:   binary.LittleEndian.Uint32(derived[4:8]),
		MagicCookie: binary.LittleEndian.Uint32(derived[8:12]),
		MagicData:   binary.LittleEndian.Uint32(derived[12:16]),
		MinPadding:  DefaultMinPadding + int(derived[16]%16),
		MaxPadding:  DefaultMaxPadding + int(derived[17]%32),
	}

	// Guard against accidental collision with standard WireGuard IDs (1..4)
	if p.MagicInit <= 4 {
		p.MagicInit += 0x1000
	}
	if p.MagicResp <= 4 {
		p.MagicResp += 0x2000
	}
	if p.MagicCookie <= 4 {
		p.MagicCookie += 0x3000
	}
	if p.MagicData <= 4 {
		p.MagicData += 0x4000
	}

	return p, nil
}

// PacketCodec manages obfuscation and de-obfuscation of WireGuard packets in memory.
type PacketCodec struct {
	params ObfsParams
	pool   *sync.Pool
}

// NewPacketCodec creates a new codec with given parameters and buffer pool.
func NewPacketCodec(params ObfsParams) *PacketCodec {
	return &PacketCodec{
		params: params,
		pool: &sync.Pool{
			New: func() any {
				b := make([]byte, 2048)
				return &b
			},
		},
	}
}

// Release returns a buffer pointer back to the pool.
func (c *PacketCodec) Release(bufPtr *[]byte) {
	if bufPtr != nil {
		c.pool.Put(bufPtr)
	}
}

// Obfuscate transforms a standard WireGuard datagram into an obfuscated datagram.
func (c *PacketCodec) Obfuscate(in []byte) ([]byte, *[]byte, error) {
	if len(in) < 4 {
		return in, nil, nil
	}

	msgType := binary.LittleEndian.Uint32(in[0:4])

	switch {
	case msgType == WgTypeInitiation && len(in) == Type1InitiationLen:
		return c.padAndObfuscate(in, c.params.MagicInit)

	case msgType == WgTypeResponse && len(in) == Type2ResponseLen:
		return c.padAndObfuscate(in, c.params.MagicResp)

	case msgType == WgTypeCookie && len(in) == Type3CookieLen:
		return c.padAndObfuscate(in, c.params.MagicCookie)

	case msgType == WgTypeData && len(in) >= Type4MinDataLen:
		bufPtr := c.pool.Get().(*[]byte)
		out := (*bufPtr)[:len(in)]
		copy(out, in)
		binary.LittleEndian.PutUint32(out[0:4], c.params.MagicData)
		return out, bufPtr, nil

	default:
		return in, nil, nil
	}
}

// padAndObfuscate appends random padding and alters the message type header.
func (c *PacketCodec) padAndObfuscate(in []byte, magicHeader uint32) ([]byte, *[]byte, error) {
	padRange := c.params.MaxPadding - c.params.MinPadding
	padLen := c.params.MinPadding
	if padRange > 0 {
		var randByte [1]byte
		_, _ = rand.Read(randByte[:])
		padLen += int(randByte[0]) % padRange
	}

	totalLen := len(in) + padLen + 2
	bufPtr := c.pool.Get().(*[]byte)
	out := (*bufPtr)[:totalLen]

	copy(out[0:len(in)], in)
	binary.LittleEndian.PutUint32(out[0:4], magicHeader)

	if padLen > 0 {
		if _, err := rand.Read(out[len(in) : len(in)+padLen]); err != nil {
			c.pool.Put(bufPtr)
			return nil, nil, err
		}
	}

	binary.BigEndian.PutUint16(out[totalLen-2:totalLen], uint16(padLen))
	return out, bufPtr, nil
}

// Deobfuscate checks if a packet has obfuscation and strips padding / restores standard headers.
func (c *PacketCodec) Deobfuscate(pkt []byte) (int, bool) {
	if len(pkt) < 4 {
		return len(pkt), false
	}

	magic := binary.LittleEndian.Uint32(pkt[0:4])

	switch magic {
	case c.params.MagicInit:
		return c.stripPaddingAndRestore(pkt, Type1InitiationLen, WgTypeInitiation)

	case c.params.MagicResp:
		return c.stripPaddingAndRestore(pkt, Type2ResponseLen, WgTypeResponse)

	case c.params.MagicCookie:
		return c.stripPaddingAndRestore(pkt, Type3CookieLen, WgTypeCookie)

	case c.params.MagicData:
		if len(pkt) >= Type4MinDataLen {
			binary.LittleEndian.PutUint32(pkt[0:4], WgTypeData)
			return len(pkt), true
		}
		return len(pkt), false

	default:
		return len(pkt), false
	}
}

// stripPaddingAndRestore validates padding trailer and restores original WireGuard header.
func (c *PacketCodec) stripPaddingAndRestore(pkt []byte, expectedBaseLen int, origType uint32) (int, bool) {
	if len(pkt) < expectedBaseLen+2 {
		return len(pkt), false
	}

	padLen := int(binary.BigEndian.Uint16(pkt[len(pkt)-2 : len(pkt)]))
	if len(pkt) != expectedBaseLen+padLen+2 {
		return len(pkt), false
	}

	binary.LittleEndian.PutUint32(pkt[0:4], origType)
	return expectedBaseLen, true
}
