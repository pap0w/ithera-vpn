package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// DefaultMTU is the standard MTU used for WireGuard virtual interfaces.
const DefaultMTU = 1420

// Create opens or creates a new TUN interface using wireguard-go/tun.
func Create(name string, mtu int) (tun.Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device %q: %w", name, err)
	}
	return dev, nil
}
