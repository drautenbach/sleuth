package firewall

import (
	"net"

	"github.com/KarpelesLab/swnat"
)

func SoftwareNAT() FirewallManager {
	externalIP := net.ParseIP("203.0.113.1")
	nat := swnat.NewIPv4(externalIP)

	return &natManager{nat}
}

type natManager struct {
	nat swnat.NAT
}

// AddAllowPort implements FirewallManager.
func (n *natManager) AddAllowPort(protocol string, port int) error {
	panic("unimplemented")
}

// Close implements FirewallManager.
func (n *natManager) Close() error {
	return nil
}

// Flush implements FirewallManager.
func (n *natManager) Flush() error {
	return nil
}

// RemoveAllowPort implements FirewallManager.
func (n *natManager) RemoveAllowPort(protocol string, port int) error {
	panic("unimplemented")
}
