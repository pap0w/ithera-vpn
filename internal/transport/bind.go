package transport

import (
	"golang.zx2c4.com/wireguard/conn"
)

// ObfsBind decorates a conn.Bind implementation with WireGuard Anti-DPI header obfuscation and dynamic padding.
type ObfsBind struct {
	bind  conn.Bind
	codec *PacketCodec
}

// NewObfsBind wraps an existing conn.Bind with the provided obfuscation parameters.
func NewObfsBind(underlying conn.Bind, params ObfsParams) *ObfsBind {
	return &ObfsBind{
		bind:  underlying,
		codec: NewPacketCodec(params),
	}
}

// Open wraps underlying Open and intercepts incoming packets via ReceiveFunc.
func (b *ObfsBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	wrappedFns := make([]conn.ReceiveFunc, len(fns))
	for i, origFn := range fns {
		wrappedFns[i] = b.wrapReceiveFunc(origFn)
	}

	return wrappedFns, actualPort, nil
}

// wrapReceiveFunc intercepts and deobfuscates incoming packets before wireguard-go parses them.
func (b *ObfsBind) wrapReceiveFunc(origFn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := origFn(packets, sizes, eps)
		if err != nil {
			return n, err
		}

		for i := 0; i < n; i++ {
			if sizes[i] < 4 {
				continue
			}
			newSize, deobfs := b.codec.Deobfuscate(packets[i][:sizes[i]])
			if deobfs {
				sizes[i] = newSize
			}
		}
		return n, nil
	}
}

// Close closes the underlying Bind.
func (b *ObfsBind) Close() error {
	return b.bind.Close()
}

// SetMark passes the fwmark through to the underlying Bind.
func (b *ObfsBind) SetMark(mark uint32) error {
	return b.bind.SetMark(mark)
}

// BatchSize returns the batch size of the underlying Bind.
func (b *ObfsBind) BatchSize() int {
	return b.bind.BatchSize()
}

// ParseEndpoint parses endpoint on the underlying Bind.
func (b *ObfsBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.bind.ParseEndpoint(s)
}

// Send intercepts outgoing WireGuard packets, applying magic headers and random padding.
func (b *ObfsBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	obfsBufs := make([][]byte, len(bufs))
	ptrsToPut := make([]*[]byte, 0, len(bufs))
	defer func() {
		for _, ptr := range ptrsToPut {
			b.codec.Release(ptr)
		}
	}()

	for i, buf := range bufs {
		if len(buf) < 4 {
			obfsBufs[i] = buf
			continue
		}

		obfsPkt, ptr, err := b.codec.Obfuscate(buf)
		if err != nil {
			obfsBufs[i] = buf
		} else {
			obfsBufs[i] = obfsPkt
			if ptr != nil {
				ptrsToPut = append(ptrsToPut, ptr)
			}
		}
	}

	return b.bind.Send(obfsBufs, ep)
}
