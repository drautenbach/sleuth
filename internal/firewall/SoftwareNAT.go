package firewall

import (
	"net"
	"sleuth/internal/constants"

	"github.com/KarpelesLab/swnat"
)

func SoftwareNAT() Firewall {
	externalIP := net.ParseIP("203.0.113.1")
	nat := swnat.NewIPv4(externalIP)

	return &natManager{nat}
}

type natManager struct {
	nat swnat.NAT
}

func (m *natManager) Name() string {
	return "software-nat"
}

func (m *natManager) Init(fwdrules []constants.FwdRule) error {
	return nil
}

func (m *natManager) Close(fwdrules []constants.FwdRule) error {
	return nil
}

// AddAllowPort implements FirewallManager.
func (n *natManager) AddAllowPort(protocol string, port int) error {
	panic("unimplemented")
}

// Flush implements FirewallManager.
func (n *natManager) Flush() error {
	return nil
}

// RemoveAllowPort implements FirewallManager.
func (n *natManager) RemoveAllowPort(protocol string, port int) error {
	panic("unimplemented")
}
