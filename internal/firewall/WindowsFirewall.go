//go:build windows
// +build windows

package firewall

func LoadFirewallManager() FirewallManager {
	fws := []Firewall{}
	fws = append(fws, SoftwareNAT())
	return FirewallManager{
		fws: fws,
	}
}
