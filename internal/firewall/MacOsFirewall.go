//go:build darwin
// +build darwin

package firewall

func InitFirewallManager() FirewallManager {
	fws := []Firewall{}
	fws = append(fws, SoftwareNAT())
	return FirewallManager{
		fws: fws,
	}
}
