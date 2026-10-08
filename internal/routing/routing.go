package routing

import (
	"errors"
	"fmt"
	"net"
)

const (
	// WireGuardOverheadIPv4 is the header overhead for WireGuard over IPv4 UDP.
	// 20 (IPv4) + 8 (UDP) + 16 (WireGuard Type 4) + 16 (Poly1305 AEAD) = 60 bytes.
	WireGuardOverheadIPv4 = 60

	// WireGuardOverheadIPv6 is the header overhead for WireGuard over IPv6 UDP.
	// 40 (IPv6) + 8 (UDP) + 16 (WireGuard Type 4) + 16 (Poly1305 AEAD) = 80 bytes.
	WireGuardOverheadIPv6 = 80

	// TCPHeaderLen is the minimum TCP header length in bytes.
	TCPHeaderLen = 20

	// IPv4HeaderLen is the standard IPv4 header length in bytes.
	IPv4HeaderLen = 20

	// IPv6HeaderLen is the standard IPv6 header length in bytes.
	IPv6HeaderLen = 40

	// DefaultTunnelMTU is a safe default MTU for typical WAN links.
	DefaultTunnelMTU = 1420
)

// SubnetPair1 represents the two /1 subnets covering the entire IPv4 address space.
var SubnetPair1 = []string{"0.0.0.0/1", "128.0.0.0/1"}

// RouteConfig provides parameters needed to configure secure tunnel routing.
type RouteConfig struct {
	InterfaceName     string
	ServerEndpointIP  string
	DefaultGatewayIP  string
	TunnelVirtualIP   string
	DNSServers        []string
	MTU               int
	EnableMSSClamping bool
}

// Validate ensures all required parameters are provided and syntactically valid.
func (c *RouteConfig) Validate() error {
	if c.InterfaceName == "" {
		return errors.New("InterfaceName is required")
	}
	if c.ServerEndpointIP == "" {
		return errors.New("ServerEndpointIP is required")
	}
	if net.ParseIP(c.ServerEndpointIP) == nil {
		return fmt.Errorf("invalid ServerEndpointIP: %q", c.ServerEndpointIP)
	}
	if c.MTU <= 0 {
		c.MTU = DefaultTunnelMTU
	}
	return nil
}

// CalculateMSS computes the optimal TCP Maximum Segment Size for a given MTU.
func CalculateMSS(mtu int, isIPv6 bool) int {
	if isIPv6 {
		return mtu - (IPv6HeaderLen + TCPHeaderLen)
	}
	return mtu - (IPv4HeaderLen + TCPHeaderLen)
}

// CalculateOptimalMTU derives the inner tunnel MTU from the underlying link MTU.
func CalculateOptimalMTU(underlayMTU int, isIPv6Underlay bool) int {
	overhead := WireGuardOverheadIPv4
	if isIPv6Underlay {
		overhead = WireGuardOverheadIPv6
	}
	targetMTU := underlayMTU - overhead
	if targetMTU < 1280 {
		// 1280 is the minimum MTU required by the IPv6 specification (RFC 8200)
		return 1280
	}
	return targetMTU
}

// SplitCIDR returns the two /1 subnets covering the entire IPv4 address space.
func SplitCIDR() []string {
	return []string{"0.0.0.0/1", "128.0.0.0/1"}
}

// Manager abstracts OS-specific route and DNS management for the VPN tunnel.
type Manager interface {
	Setup(cfg RouteConfig) error
	Teardown(cfg RouteConfig) error
}
