package firewall

import (
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
