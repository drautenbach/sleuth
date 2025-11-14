//go:build darwin
// +build darwin

package firewall

// NewFirewallManager auto-detects nft vs iptables and returns a backend.
// Returns nil if neither is available.
func InitFirewall() FirewallManager {
	return nil
}
