package device

import (
	"fmt"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Device wraps wireguard-go's *device.Device with clean lifecycle controls.
type Device struct {
	dev    *device.Device
	tunDev tun.Device
	logger *device.Logger
}

// New creates and starts a new wireguard-go Device using the default UDP bind.
func New(tunDev tun.Device, cfg Config, verbose bool) (*Device, error) {
	return NewWithBind(tunDev, conn.NewDefaultBind(), cfg, verbose)
}

// NewWithBind creates and starts a new wireguard-go Device with a custom conn.Bind transport.
func NewWithBind(tunDev tun.Device, bind conn.Bind, cfg Config, verbose bool) (*Device, error) {
	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, "(ithera) ")

	wgDev := device.NewDevice(tunDev, bind, logger)

	d := &Device{
		dev:    wgDev,
		tunDev: tunDev,
		logger: logger,
	}

	if err := d.Configure(cfg); err != nil {
		d.Close()
		return nil, fmt.Errorf("failed to configure wireguard device: %w", err)
	}

	if err := d.Up(); err != nil {
		d.Close()
		return nil, fmt.Errorf("failed to bring wireguard device up: %w", err)
	}

	return d, nil
}

// Configure applies settings to the device using UAPI IpcSet.
func (d *Device) Configure(cfg Config) error {
	uapi, err := BuildUAPIString(cfg)
	if err != nil {
		return fmt.Errorf("failed to build UAPI config: %w", err)
	}

	if err := d.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("IpcSet error: %w", err)
	}
	return nil
}

// Up brings the device up.
func (d *Device) Up() error {
	return d.dev.Up()
}

// Down brings the device down.
func (d *Device) Down() error {
	return d.dev.Down()
}

// Close closes the WireGuard device and the underlying TUN interface.
func (d *Device) Close() {
	if d.dev != nil {
		d.dev.Close()
	}
}

// Wait returns a channel that blocks until the device closes.
func (d *Device) Wait() chan struct{} {
	return d.dev.Wait()
}

// IpcGet returns the current device configuration in UAPI format.
func (d *Device) IpcGet() (string, error) {
	return d.dev.IpcGet()
}
