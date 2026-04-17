package firewall

import (
	"sleuth/internal/db"
)

// FirewallManager is a minimal interface for managing firewall rules.
type FirewallManager struct {
	fws []Firewall
	fw  Firewall
	db  *db.Db
}

func (m *FirewallManager) Init(db *db.Db) {
	m.db = db
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

	rules := m.db.GetFwdRules()

	if m.fw != nil {
		m.fw.Close(rules)
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

	if m.fw != nil {
		m.fw.Init(rules)
	}
}
