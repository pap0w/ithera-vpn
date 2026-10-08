//go:build linux

package tun

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// ConfigureInterface assigns an IP address (CIDR notation) to the TUN interface and brings it UP using Linux netlink.
func ConfigureInterface(ifname string, ipCIDR string, mtu int) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("netlink: interface %q not found: %w", ifname, err)
	}

	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("netlink: failed to set MTU on %q: %w", ifname, err)
		}
	}

	if ipCIDR != "" {
		addr, err := netlink.ParseAddr(ipCIDR)
		if err != nil {
			return fmt.Errorf("netlink: invalid CIDR %q: %w", ipCIDR, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("netlink: failed to add address %s to %q: %w", ipCIDR, ifname, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netlink: failed to bring up interface %q: %w", ifname, err)
	}

	return nil
}
