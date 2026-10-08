package device

import (
	"strings"
	"testing"

	"github.com/pap0w/ithera-vpn/internal/crypto"
)

func TestBuildUAPIString(t *testing.T) {
	priv, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("crypto.GeneratePrivateKey failed: %v", err)
	}
	pub, err := crypto.PublicKey(priv)
	if err != nil {
		t.Fatalf("crypto.PublicKey failed: %v", err)
	}

	peerPriv, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("crypto.GeneratePrivateKey failed: %v", err)
	}
	peerPub, err := crypto.PublicKey(peerPriv)
	if err != nil {
		t.Fatalf("crypto.PublicKey failed: %v", err)
	}

	cfg := Config{
		PrivateKey:   crypto.KeyToBase64(priv),
		ListenPort:   51820,
		ReplacePeers: true,
		Peers: []PeerConfig{
			{
				PublicKey:           crypto.KeyToBase64(peerPub),
				Endpoint:            "10.200.0.1:51820",
				AllowedIPs:          []string{"10.0.0.2/32"},
				PersistentKeepalive: 25,
			},
		},
	}

	uapi, err := BuildUAPIString(cfg)
	if err != nil {
		t.Fatalf("BuildUAPIString failed: %v", err)
	}

	// Verify Hex conversion
	expectedPrivHex := "private_key=" + crypto.KeyToHex(priv)
	if !strings.Contains(uapi, expectedPrivHex) {
		t.Errorf("expected UAPI string to contain %q, got:\n%s", expectedPrivHex, uapi)
	}

	expectedPeerPubHex := "public_key=" + crypto.KeyToHex(peerPub)
	if !strings.Contains(uapi, expectedPeerPubHex) {
		t.Errorf("expected UAPI string to contain %q, got:\n%s", expectedPeerPubHex, uapi)
	}

	if !strings.Contains(uapi, "listen_port=51820") {
		t.Errorf("missing listen_port")
	}
	if !strings.Contains(uapi, "endpoint=10.200.0.1:51820") {
		t.Errorf("missing endpoint")
	}
	if !strings.Contains(uapi, "allowed_ip=10.0.0.2/32") {
		t.Errorf("missing allowed_ip")
	}
	if !strings.Contains(uapi, "persistent_keepalive_interval=25") {
		t.Errorf("missing persistent_keepalive_interval")
	}
	_ = pub
}
