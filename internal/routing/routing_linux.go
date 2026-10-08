//go:build linux

package routing

import (
	"fmt"
	"os/exec"
	"strings"
)

// LinuxManager implements Manager for Linux using ip and iptables.
type LinuxManager struct{}

// NewManager returns a new LinuxManager instance.
func NewManager() Manager {
	return &LinuxManager{}
}

// Setup installs the /1 routes, host route to endpoint, and TCP MSS clamping.
func (m *LinuxManager) Setup(cfg RouteConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	// 1. Install specific /32 route to VPN server endpoint via default physical gateway
	if cfg.DefaultGatewayIP != "" {
		cmd := exec.Command("ip", "route", "replace", cfg.ServerEndpointIP+"/32", "via", cfg.DefaultGatewayIP)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add endpoint host route: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	}

	// 2. Install /1 routes covering all IPv4 traffic to interface
	for _, subnet := range SubnetPair1 {
		cmd := exec.Command("ip", "route", "replace", subnet, "dev", cfg.InterfaceName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add /1 route %s: %w (output: %s)", subnet, err, strings.TrimSpace(string(out)))
		}
	}

	// 3. Configure TCP MSS Clamping to prevent fragmentation and blackholes
	if cfg.EnableMSSClamping {
		mss := CalculateMSS(cfg.MTU, false)
		cmd := exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-o", cfg.InterfaceName,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss))
		_ = cmd.Run() // Best effort if iptables is available and permissions granted
	}

	// 4. DNS Configuration (systemd-resolved or interface DNS)
	if len(cfg.DNSServers) > 0 {
		dnsArgs := append([]string{"dns", cfg.InterfaceName}, cfg.DNSServers...)
		_ = exec.Command("resolvectl", dnsArgs...).Run()
		_ = exec.Command("resolvectl", "domain", cfg.InterfaceName, "~.").Run()
	}

	return nil
}

// Teardown cleanly removes the installed routes and firewall rules.
func (m *LinuxManager) Teardown(cfg RouteConfig) error {
	var errs []string

	// Remove /1 routes
	for _, subnet := range SubnetPair1 {
		cmd := exec.Command("ip", "route", "del", subnet, "dev", cfg.InterfaceName)
		if out, err := cmd.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("del %s: %v (%s)", subnet, err, strings.TrimSpace(string(out))))
		}
	}

	// Remove endpoint host route
	if cfg.ServerEndpointIP != "" {
		cmd := exec.Command("ip", "route", "del", cfg.ServerEndpointIP+"/32")
		_ = cmd.Run()
	}

	// Remove MSS clamping rule
	if cfg.EnableMSSClamping {
		mss := CalculateMSS(cfg.MTU, false)
		cmd := exec.Command("iptables", "-t", "mangle", "-D", "FORWARD", "-o", cfg.InterfaceName,
			"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss))
		_ = cmd.Run()
	}

	// Revert DNS
	if len(cfg.DNSServers) > 0 {
		_ = exec.Command("resolvectl", "revert", cfg.InterfaceName).Run()
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}
