package firewall

// FirewallManager is a minimal interface for managing firewall rules.
type FirewallManager interface {
	// AddAllowPort allows inbound traffic for protocol ("tcp"/"udp") on port.
	AddAllowPort(protocol string, port int) error
	// RemoveAllowPort removes an allow rule created by AddAllowPort.
	RemoveAllowPort(protocol string, port int) error
	// Flush removes all rules created by this manager (best-effort).
	Flush() error
	// Close releases any resources (best-effort).
	Close() error
}

// WindowsFirewallManager implements FirewallManager for Windows.
type WindowsFirewallManager struct{}

// AddAllowPort allows inbound traffic for protocol ("tcp"/"udp") on port.
func (w *WindowsFirewallManager) AddAllowPort(protocol string, port int) error {
	// Implementation for Windows
	return nil
}

// RemoveAllowPort removes an allow rule created by AddAllowPort.
func (w *WindowsFirewallManager) RemoveAllowPort(protocol string, port int) error {
	// Implementation for Windows
	return nil
}

// Flush removes all rules created by this manager (best-effort).
func (w *WindowsFirewallManager) Flush() error {
	// Implementation for Windows
	return nil
}

// Close releases any resources (best-effort).
func (w *WindowsFirewallManager) Close() error {
	// Implementation for Windows
	return nil
}

// MacOSFirewallManager implements FirewallManager for macOS.
type MacOSFirewallManager struct{}

// AddAllowPort allows inbound traffic for protocol ("tcp"/"udp") on port.
func (m *MacOSFirewallManager) AddAllowPort(protocol string, port int) error {
	// Implementation for macOS
	return nil
}

// RemoveAllowPort removes an allow rule created by AddAllowPort.
func (m *MacOSFirewallManager) RemoveAllowPort(protocol string, port int) error {
	// Implementation for macOS
	return nil
}

// Flush removes all rules created by this manager (best-effort).
func (m *MacOSFirewallManager) Flush() error {
	// Implementation for macOS
	return nil
}

// Close releases any resources (best-effort).
func (m *MacOSFirewallManager) Close() error {
	// Implementation for macOS
	return nil
}
