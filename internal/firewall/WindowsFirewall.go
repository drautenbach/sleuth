//go:build windows
// +build windows

package firewall

func InitFirewallManager() FirewallManager {
	fws := []Firewall{}
	fws = append(fws, SoftwareNAT())
	return FirewallManager{
		fws: fws,
	}
}
