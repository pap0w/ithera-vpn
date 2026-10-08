package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pap0w/ithera-vpn/internal/crypto"
	"github.com/pap0w/ithera-vpn/internal/device"
	"github.com/pap0w/ithera-vpn/internal/transport"
	"github.com/pap0w/ithera-vpn/internal/tun"
	"golang.zx2c4.com/wireguard/conn"
)

func main() {
	ifname := flag.String("iface", "ithera-srv", "TUN interface name")
	mtu := flag.Int("mtu", 1420, "TUN interface MTU")
	ipCIDR := flag.String("ip", "10.0.0.1/24", "Virtual IP and CIDR mask to assign to TUN")
	port := flag.Int("port", 51820, "UDP port to listen on")
	privKeyStr := flag.String("privkey", "", "Base64 or Hex private key (auto-generated if empty)")
	peerPubKeyStr := flag.String("peer-pubkey", "", "Peer public key (Base64 or Hex)")
	peerAllowedIP := flag.String("peer-allowed-ip", "10.0.0.2/32", "AllowedIP for the peer")
	obfsKey := flag.String("obfs-key", "", "Shared secret for Anti-DPI WireGuard header obfuscation (empty to disable)")
	verbose := flag.Bool("v", false, "Enable verbose WireGuard logs")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("Starting itherasrv", "iface", *ifname, "port", *port, "ip", *ipCIDR)

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
		logger.Info("Generated ephemeral keys",
			"private_key", crypto.KeyToBase64(privKey),
			"public_key", crypto.KeyToBase64(pubKey))
	} else {
		privKey, err = crypto.ParseKey(*privKeyStr)
		if err != nil {
			logger.Error("Invalid private key", "err", err)
			os.Exit(1)
		}
		pubKey, _ := crypto.PublicKey(privKey)
		logger.Info("Loaded keys", "public_key", crypto.KeyToBase64(pubKey))
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

	// 3. Prepare WireGuard configuration
	cfg := device.Config{
		PrivateKey:   crypto.KeyToBase64(privKey),
		ListenPort:   *port,
		ReplacePeers: true,
	}

	if *peerPubKeyStr != "" {
		cfg.Peers = append(cfg.Peers, device.PeerConfig{
			PublicKey:  *peerPubKeyStr,
			AllowedIPs: []string{*peerAllowedIP},
		})
		logger.Info("Configured peer", "public_key", *peerPubKeyStr, "allowed_ip", *peerAllowedIP)
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

	logger.Info("itherasrv running and listening. Press Ctrl+C to stop.")

	// Wait for termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Info("Received signal, shutting down...", "signal", sig.String())
	case <-wgDev.Wait():
		logger.Info("WireGuard device closed.")
	}

	fmt.Println("itherasrv terminated cleanly.")
}
