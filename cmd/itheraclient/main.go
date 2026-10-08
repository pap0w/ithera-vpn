package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pap0w/ithera-vpn/internal/crypto"
	"github.com/pap0w/ithera-vpn/internal/device"
	"github.com/pap0w/ithera-vpn/internal/routing"
	"github.com/pap0w/ithera-vpn/internal/transport"
	"github.com/pap0w/ithera-vpn/internal/tun"
	"golang.zx2c4.com/wireguard/conn"
)

func main() {
	ifname := flag.String("iface", "ithera-cli", "TUN interface name")
	mtu := flag.Int("mtu", 1420, "TUN interface MTU")
	ipCIDR := flag.String("ip", "10.0.0.2/24", "Virtual IP and CIDR mask to assign to TUN")
	port := flag.Int("port", 0, "Local UDP port to bind (0 for ephemeral)")
	privKeyStr := flag.String("privkey", "", "Base64 or Hex private key (auto-generated if empty)")
	serverPubKeyStr := flag.String("server-pubkey", "", "Server public key (Base64 or Hex, required)")
	serverEndpoint := flag.String("server-endpoint", "", "Server endpoint host:port (required)")
	allowedIPsStr := flag.String("allowed-ips", "10.0.0.0/24", "Comma-separated AllowedIPs for server peer")
	keepalive := flag.Int("keepalive", 25, "Persistent keepalive interval in seconds (0 to disable)")
	obfsKey := flag.String("obfs-key", "", "Shared secret for Anti-DPI WireGuard header obfuscation (empty to disable)")
	enableRouting := flag.Bool("routing", false, "Enable automatic full-tunnel /1 routing and DNS enforcement")
	defaultGW := flag.String("gateway", "", "Physical default gateway IP (for endpoint host route)")
	dnsServers := flag.String("dns", "1.1.1.1,8.8.8.8", "Comma-separated DNS servers to configure if routing is enabled")
	verbose := flag.Bool("v", false, "Enable verbose WireGuard logs")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if *serverPubKeyStr == "" || *serverEndpoint == "" {
		logger.Error("Both -server-pubkey and -server-endpoint are required")
		flag.Usage()
		os.Exit(1)
	}

	logger.Info("Starting itheraclient", "iface", *ifname, "ip", *ipCIDR, "server", *serverEndpoint)

	// Key handling
	var privKey [crypto.KeyLen]byte
	var err error
	if *privKeyStr == "" {
		privKey, err = crypto.GeneratePrivateKey()
		if err != nil {
			logger.Error("Failed to generate private key", "err", err)
			os.Exit(1)
		}
		pubKey, _ := crypto.PublicKey(privKey)
		logger.Info("Generated client ephemeral keys",
			"private_key", crypto.KeyToBase64(privKey),
			"public_key", crypto.KeyToBase64(pubKey))
	} else {
		privKey, err = crypto.ParseKey(*privKeyStr)
		if err != nil {
			logger.Error("Invalid client private key", "err", err)
			os.Exit(1)
		}
		pubKey, _ := crypto.PublicKey(privKey)
		logger.Info("Loaded client keys", "public_key", crypto.KeyToBase64(pubKey))
	}

	// 1. Create TUN device
	tunDev, err := tun.Create(*ifname, *mtu)
	if err != nil {
		logger.Error("Failed to create TUN device", "err", err)
		os.Exit(1)
	}
	defer tunDev.Close()

	// 2. Configure network interface (IP, MTU, UP)
	if err := tun.ConfigureInterface(*ifname, *ipCIDR, *mtu); err != nil {
		logger.Warn("Interface network configuration returned warning/error", "err", err)
	} else {
		logger.Info("Configured TUN network interface", "iface", *ifname, "ip", *ipCIDR)
	}

	// 3. Prepare WireGuard configuration with Server peer
	var allowedIPs []string
	for _, raw := range strings.Split(*allowedIPsStr, ",") {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" {
			allowedIPs = append(allowedIPs, trimmed)
		}
	}

	cfg := device.Config{
		PrivateKey:   crypto.KeyToBase64(privKey),
		ListenPort:   *port,
		ReplacePeers: true,
		Peers: []device.PeerConfig{
			{
				PublicKey:           *serverPubKeyStr,
				Endpoint:            *serverEndpoint,
				AllowedIPs:          allowedIPs,
				PersistentKeepalive: *keepalive,
			},
		},
	}

	// 4. Start WireGuard device
	var wgDev *device.Device
	if *obfsKey != "" {
		params, err := transport.DeriveObfsParams([]byte(*obfsKey))
		if err != nil {
			logger.Error("Failed to derive obfuscation parameters", "err", err)
			os.Exit(1)
		}
		obfsBind := transport.NewObfsBind(conn.NewDefaultBind(), params)
		logger.Info("Enabled Anti-DPI WireGuard header obfuscation and dynamic padding")
		wgDev, err = device.NewWithBind(tunDev, obfsBind, cfg, *verbose)
	} else {
		wgDev, err = device.New(tunDev, cfg, *verbose)
	}
	if err != nil {
		logger.Error("Failed to initialize WireGuard device", "err", err)
		os.Exit(1)
	}
	defer wgDev.Close()

	// 5. Optional Routing Manager Setup (/1 full tunnel)
	routeMgr := routing.NewManager()
	var routeCfg routing.RouteConfig
	if *enableRouting {
		serverHost := strings.Split(*serverEndpoint, ":")[0]
		var dnsList []string
		for _, d := range strings.Split(*dnsServers, ",") {
			trimmed := strings.TrimSpace(d)
			if trimmed != "" {
				dnsList = append(dnsList, trimmed)
			}
		}

		routeCfg = routing.RouteConfig{
			InterfaceName:     *ifname,
			ServerEndpointIP:  serverHost,
			DefaultGatewayIP:  *defaultGW,
			TunnelVirtualIP:   strings.Split(*ipCIDR, "/")[0],
			DNSServers:        dnsList,
			MTU:               *mtu,
			EnableMSSClamping: true,
		}

		if err := routeMgr.Setup(routeCfg); err != nil {
			logger.Warn("Failed to configure full-tunnel routing", "err", err)
		} else {
			logger.Info("Configured /1 full-tunnel routing and DNS enforcement", "iface", *ifname)
			defer func() {
				logger.Info("Tearing down tunnel routing rules...")
				_ = routeMgr.Teardown(routeCfg)
			}()
		}
	}

	logger.Info("itheraclient connected to gateway peer. Press Ctrl+C to disconnect.")

	// Wait for termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Info("Received signal, disconnecting...", "signal", sig.String())
	case <-wgDev.Wait():
		logger.Info("WireGuard device closed.")
	}

	fmt.Println("itheraclient disconnected cleanly.")
}
