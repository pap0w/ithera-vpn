package device

import (
	"fmt"
	"strings"

	"github.com/pap0w/ithera-vpn/internal/crypto"
)

// PeerConfig defines a WireGuard peer configuration for the UAPI.
type PeerConfig struct {
	// PublicKey in either Base64 or Hex format.
	PublicKey string
	// Endpoint in host:port format. Optional.
	Endpoint string
	// AllowedIPs list of CIDR strings (e.g. "10.0.0.2/32").
	AllowedIPs []string
	// PersistentKeepalive in seconds. Optional (0 to disable).
	PersistentKeepalive int
}

// Config defines the local WireGuard device configuration.
type Config struct {
	// PrivateKey in either Base64 or Hex format.
	PrivateKey string
	// ListenPort for receiving incoming UDP packets. (0 for ephemeral/client).
	ListenPort int
	// ReplacePeers when true clears all existing peers before adding new ones.
	ReplacePeers bool
	// Peers list to register.
	Peers []PeerConfig
}

// BuildUAPIString builds the standard WireGuard UAPI string expected by wireguard-go IpcSet.
// All keys in WireGuard UAPI must be formatted in lower-case hex (64 chars).
func BuildUAPIString(cfg Config) (string, error) {
	var sb strings.Builder

	if cfg.PrivateKey != "" {
		key, err := crypto.ParseKey(cfg.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("invalid private_key: %w", err)
		}
		sb.WriteString(fmt.Sprintf("private_key=%s\n", crypto.KeyToHex(key)))
	}

	if cfg.ListenPort >= 0 {
		sb.WriteString(fmt.Sprintf("listen_port=%d\n", cfg.ListenPort))
	}

	if cfg.ReplacePeers {
		sb.WriteString("replace_peers=true\n")
	}

	for _, peer := range cfg.Peers {
		if peer.PublicKey == "" {
			continue
		}
		pubKey, err := crypto.ParseKey(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("invalid peer public_key %q: %w", peer.PublicKey, err)
		}

		sb.WriteString(fmt.Sprintf("public_key=%s\n", crypto.KeyToHex(pubKey)))

		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
		}

		if peer.PersistentKeepalive > 0 {
			sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}

		for _, allowedIP := range peer.AllowedIPs {
			trimmed := strings.TrimSpace(allowedIP)
			if trimmed != "" {
				sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", trimmed))
			}
		}
	}

	return sb.String(), nil
}
