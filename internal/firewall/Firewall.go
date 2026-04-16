package firewall

// FirewallManager is a minimal interface for managing firewall rules.
type Firewall interface {
	Name() string
	// AddAllowPort allows inbound traffic for protocol ("tcp"/"udp") on port.
	AddAllowPort(protocol string, port int) error
	// RemoveAllowPort removes an allow rule created by AddAllowPort.
	RemoveAllowPort(protocol string, port int) error
	// Flush removes all rules created by this manager (best-effort).
	Flush() error
	// Close releases any resources (best-effort).
	Close() error
}
