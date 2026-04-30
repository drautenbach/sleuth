package firewall

import (
	"errors"
	"sleuth/internal/constants"
)

func eBpfFirewall() (Firewall, error) {

	return &eBpf{}, nil
}

type eBpf struct {
}

func (m *eBpf) Name() string {
	return "eBpf"
}

func (m *eBpf) Init(fwdrules []constants.FwdRule) error {
	return nil
}

func (m *eBpf) Close(fwdrules []constants.FwdRule) error {
	return nil
}

func (m *eBpf) AddForwardRule(fwdrule *constants.FwdRule) error {
	return errors.New("Not implemented")
}

func (m *eBpf) RemoveForwardRule(fwdrule *constants.FwdRule) error {
	return errors.New("Not implemented")
}

func (m *eBpf) GetStats() ([]Stat, error) {
	return nil, nil
}

// AddAllowPort implements FirewallManager.
func (n *eBpf) AddAllowPort(protocol string, port int) error {
	return nil
}

// Flush implements FirewallManager.
func (n *eBpf) Flush() error {
	return nil
}

// RemoveAllowPort implements FirewallManager.
func (n *eBpf) RemoveAllowPort(protocol string, port int) error {
	return nil
}
