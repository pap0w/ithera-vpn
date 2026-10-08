//go:build !linux && !windows

package routing

import "errors"

// FallbackManager provides a stub manager for unsupported OS targets.
type FallbackManager struct{}

// NewManager returns a stub Manager.
func NewManager() Manager {
	return &FallbackManager{}
}

func (m *FallbackManager) Setup(cfg RouteConfig) error {
	return errors.New("routing manager not supported on this platform")
}

func (m *FallbackManager) Teardown(cfg RouteConfig) error {
	return nil
}
