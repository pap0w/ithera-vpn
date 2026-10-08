//go:build windows

package tun

import (
	"fmt"
	"net"
	"os/exec"
)

// ConfigureInterface configures the IP address on Windows using netsh or PowerShell.
func ConfigureInterface(ifname string, ipCIDR string, mtu int) error {
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", ipCIDR, err)
	}

	mask := net.IP(ipNet.Mask)
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", ifname),
		"source=static",
		fmt.Sprintf("addr=%s", ip.String()),
		fmt.Sprintf("mask=%s", mask.String()))

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh failed (%v): %s", err, string(out))
	}

	return nil
}
