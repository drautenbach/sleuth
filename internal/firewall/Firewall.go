package firewall

import (
	"sleuth/internal/constants"
)

// FirewallManager is a minimal interface for managing firewall rules.
type Firewall interface {
	Name() string
	Init(fwdrules []constants.FwdRule) error
	// Close releases any resources (best-effort).
	Close(fwdrules []constants.FwdRule) error

	AddForwardRule(fwdrule *constants.FwdRule) error
	RemoveForwardRule(fwdrule *constants.FwdRule) error

	// AddAllowPort allows inbound traffic for protocol ("tcp"/"udp") on port.
	AddAllowPort(protocol string, port int) error
	// RemoveAllowPort removes an allow rule created by AddAllowPort.
	RemoveAllowPort(protocol string, port int) error
	// Flush removes all rules created by this manager (best-effort).
	Flush() error
}
