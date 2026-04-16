package firewall

// FirewallManager is a minimal interface for managing firewall rules.
type FirewallManager struct {
	fws []Firewall
	fw  Firewall
}

func (m *FirewallManager) AvailableFirewalls() []string {
	firewalls := []string{"default", "none"}
	for _, m := range m.fws {
		firewalls = append(firewalls, m.Name())
	}
	return firewalls
}

func (m *FirewallManager) SetActiveFirewall(firewall string) {
	if m.fw != nil && m.fw.Name() == firewall {
		return
	}
	if firewall == "none" {
		m.fw = nil
		return
	}

	found := false
	for _, fw := range m.fws {
		if firewall == fw.Name() {
			m.fw = fw
			found = true
			break
		}
	}

	if found == false && len(m.fws) > 0 {
		m.fw = m.fws[0]
	}
}
