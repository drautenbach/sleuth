//go:build linux
// +build linux

package firewall

import (
	"os/exec"
)

// NewFirewallManager auto-detects nft vs iptables and returns a backend.
// Returns nil if neither is available.
func InitFirewall() FirewallManager {
	if _, err := exec.LookPath("nft"); err == nil {
		if m, err := NewNftablesManager(); err == nil {
			return m
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		if m, err := NewIptablesManager(); err == nil {
			return m
		}
	}
	return nil
}
