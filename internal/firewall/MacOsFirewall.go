//go:build darwin
// +build darwin

package firewall

func LoadFirewallManager() FirewallManager {
	fws := []Firewall{}
	fws = append(fws, SoftwareNAT())
	return FirewallManager{
		fws: fws,
	}
}
