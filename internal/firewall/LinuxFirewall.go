//go:build linux
// +build linux

package firewall

import (
	"os/exec"
)

func LoadFirewallManager() FirewallManager {
	fws := []Firewall{}

	if _, err := exec.LookPath("nft"); err == nil {
		if m, err := NewNftablesManager(); err == nil {
			fws = append(fws, m)
		}
	}

	if _, err := exec.LookPath("iptables"); err == nil {
		if m, err := NewIptablesManager(); err == nil {
			fws = append(fws, m)
		}
	}

	if _, err := exec.LookPath("ebpf"); err == nil {
		if m, err := eBpfFirewall(); err == nil {
			fws = append(fws, m)
		}
	}

	fws = append(fws, SoftwareNAT())

	return FirewallManager{
		fws: fws,
	}
}
