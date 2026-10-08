//go:build windows

package routing

import (
	"fmt"
	"os/exec"
	"strings"
)

// WindowsManager implements Manager for Windows using route and netsh.
type WindowsManager struct{}

// NewManager returns a new WindowsManager instance.
func NewManager() Manager {
	return &WindowsManager{}
}

// Setup configures routing and DNS on Windows.
func (m *WindowsManager) Setup(cfg RouteConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	gateway := cfg.TunnelVirtualIP
	if gateway == "" {
		gateway = "0.0.0.0"
	}

	// 1. Host route for Server endpoint via physical default gateway
	if cfg.DefaultGatewayIP != "" {
		cmd := exec.Command("route", "add", cfg.ServerEndpointIP, "mask", "255.255.255.255", cfg.DefaultGatewayIP, "metric", "1")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add endpoint host route: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}

	// 2. Add /1 routes (0.0.0.0/1 and 128.0.0.0/1)
	subnets := []struct {
		dest string
		mask string
	}{
		{"0.0.0.0", "128.0.0.0"},
		{"128.0.0.0", "128.0.0.0"},
	}

	for _, s := range subnets {
		cmd := exec.Command("route", "add", s.dest, "mask", s.mask, gateway, "metric", "5")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route %s mask %s: %w (%s)", s.dest, s.mask, err, strings.TrimSpace(string(out)))
		}
	}

	// 3. DNS configuration via netsh
	if len(cfg.DNSServers) > 0 {
		primaryDNS := cfg.DNSServers[0]
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
			fmt.Sprintf("name=%s", cfg.InterfaceName), "static", primaryDNS, "primary")
		_ = cmd.Run()

		for i := 1; i < len(cfg.DNSServers); i++ {
			addCmd := exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
				fmt.Sprintf("name=%s", cfg.InterfaceName), cfg.DNSServers[i], fmt.Sprintf("index=%d", i+1))
			_ = addCmd.Run()
		}
	}

	return nil
}

// Teardown cleanly removes the installed routes from the Windows routing table.
func (m *WindowsManager) Teardown(cfg RouteConfig) error {
	var errs []string

	// Delete /1 routes
	for _, dest := range []string{"0.0.0.0", "128.0.0.0"} {
		cmd := exec.Command("route", "delete", dest, "mask", "128.0.0.0")
		if out, err := cmd.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("del %s: %v (%s)", dest, err, strings.TrimSpace(string(out))))
		}
	}

	// Delete endpoint host route
	if cfg.ServerEndpointIP != "" {
		cmd := exec.Command("route", "delete", cfg.ServerEndpointIP)
		_ = cmd.Run()
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}
