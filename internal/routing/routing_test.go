package routing

import (
	"testing"
)

func TestCalculateMSS(t *testing.T) {
	tests := []struct {
		name     string
		mtu      int
		isIPv6   bool
		expected int
	}{
		{"IPv4 standard MTU 1420", 1420, false, 1380},
		{"IPv4 Ethernet MTU 1500", 1500, false, 1460},
		{"IPv6 standard MTU 1420", 1420, true, 1360},
		{"IPv6 Ethernet MTU 1500", 1500, true, 1440},
		{"Conservative MTU 1280 IPv4", 1280, false, 1240},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateMSS(tt.mtu, tt.isIPv6)
			if got != tt.expected {
				t.Errorf("CalculateMSS(%d, %v) = %d; want %d", tt.mtu, tt.isIPv6, got, tt.expected)
			}
		})
	}
}

func TestCalculateOptimalMTU(t *testing.T) {
	tests := []struct {
		name           string
		underlayMTU    int
		isIPv6Underlay bool
		expected       int
	}{
		{"Standard 1500 IPv4", 1500, false, 1440},
		{"Standard 1500 IPv6", 1500, true, 1420},
		{"PPPoE 1492 IPv4", 1492, false, 1432},
		{"Low MTU boundary clamped to RFC min 1280", 1300, false, 1280},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateOptimalMTU(tt.underlayMTU, tt.isIPv6Underlay)
			if got != tt.expected {
				t.Errorf("CalculateOptimalMTU(%d, %v) = %d; want %d", tt.underlayMTU, tt.isIPv6Underlay, got, tt.expected)
			}
		})
	}
}

func TestRouteConfigValidation(t *testing.T) {
	// Missing InterfaceName
	cfg1 := RouteConfig{
		ServerEndpointIP: "1.2.3.4",
	}
	if err := cfg1.Validate(); err == nil {
		t.Errorf("expected error for empty InterfaceName, got nil")
	}

	// Missing ServerEndpointIP
	cfg2 := RouteConfig{
		InterfaceName: "ithera-cli",
	}
	if err := cfg2.Validate(); err == nil {
		t.Errorf("expected error for empty ServerEndpointIP, got nil")
	}

	// Invalid IP
	cfg3 := RouteConfig{
		InterfaceName:    "ithera-cli",
		ServerEndpointIP: "invalid-ip",
	}
	if err := cfg3.Validate(); err == nil {
		t.Errorf("expected error for invalid ServerEndpointIP, got nil")
	}

	// Valid config
	cfg4 := RouteConfig{
		InterfaceName:    "ithera-cli",
		ServerEndpointIP: "1.2.3.4",
		MTU:              0, // Should be defaulted
	}
	if err := cfg4.Validate(); err != nil {
		t.Errorf("unexpected error for valid config: %v", err)
	}
	if cfg4.MTU != DefaultTunnelMTU {
		t.Errorf("expected MTU to default to %d, got %d", DefaultTunnelMTU, cfg4.MTU)
	}
}

func TestSplitCIDR(t *testing.T) {
	subnets := SplitCIDR()
	if len(subnets) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(subnets))
	}
	if subnets[0] != "0.0.0.0/1" || subnets[1] != "128.0.0.0/1" {
		t.Errorf("unexpected subnets: %v", subnets)
	}
}
