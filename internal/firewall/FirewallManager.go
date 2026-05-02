package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"time"
)

type Stat struct {
	Source      net.IPNet
	Destination net.IPNet
	Bytes       uint64
}

// FirewallManager is a minimal interface for managing firewall rules.
type FirewallManager struct {
	fws     []Firewall
	fw      Firewall
	db      *db.Db
	ip_seed uint16
}

func (m *FirewallManager) Init(db *db.Db) {
	m.db = db
	m.ip_seed = 1

	ticker := time.NewTicker(time.Second * 60)
	go func() {
		for {
			<-ticker.C
			m.ReviewFwdRules()
		}
	}()
}

func (m *FirewallManager) IsActive() bool {
	return m.fw != nil && m.db != nil
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
		for _, r := range rules {
			if time.Now().After(r.CacheExpiry) || time.Now().After(r.DNSExpiry) {
				m.db.DeleteFwdRule(&r)
			}
		}
		m.fw.Init(m.db.GetFwdRules())
	}
}

func ip4ToInt(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP")
	}

	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}

	return binary.BigEndian.Uint32(ip), nil
}

func intToIP4(n uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.String()
}

func IP4fromOffset(offset uint16) string {
	ip, _ := ip4ToInt("10.0.0.1")
	return intToIP4(ip + uint32(offset))
}

func (m *FirewallManager) AllocateIPv4(clientIP string, name string, qtype uint16, actualIP string, ttl uint32) (string, error) {
	if ttl < 90 {
		ttl = 90
	}
	r := &constants.FwdRule{
		Since:     time.Now(),
		Until:     time.Now(),
		ClientIP:  clientIP,
		Hostname:  name,
		OrigIP:    actualIP,
		QType:     qtype,
		DNSExpiry: time.Now().Add(time.Second * time.Duration(ttl)),
		BytesUsed: 0,
	}
	max_len := uint16(65535) //256*256
	rules := m.db.GetFwdRules()
	// Assume rules are sorted by DestIPOffset ascending
	expected := uint16(1)
	r.DestIPOffset = 0
	for _, rule := range rules {
		if rule.DestIPOffset > expected {
			r.DestIPOffset = expected
			break
		}
		expected = rule.DestIPOffset + 1
	}
	if r.DestIPOffset == 0 && expected <= max_len {
		r.DestIPOffset = expected
	}

	if r.DestIPOffset == 0 {
		return "", errors.New("no available IP offset")
	} else {
		err := m.db.CreateFwdRule(r, time.Now().Add(time.Duration(330)*time.Second))
		if err == nil && m.fw != nil {
			m.fw.AddForwardRule(r)
		}
		return IP4fromOffset(r.DestIPOffset), err
	}

}

func (m *FirewallManager) IPCacheLookup(clientIP string, name string, qtype uint16) *constants.FwdRule {
	r := m.db.GetFwdRuleByHostname(clientIP, name, qtype)
	if r != nil {
		if time.Now().After(r.DNSExpiry) {
			err := m.fw.RemoveForwardRule(r)
			if err == nil {
				m.db.DeleteFwdRule(r)
			}
			return nil
		}
		m.db.ExtendFwdRule(r, time.Now().Add(time.Second*630))
	}
	return r
}

func (m *FirewallManager) ReviewFwdRules() {
	rules := m.db.GetFwdRules()

	if stats, err := m.fw.GetStats(); err == nil {
		for i := range stats {
			source := stats[i].Source.IP.String()
			destination := stats[i].Destination.IP.String()
			if stats[i].Bytes > 0 {
				for _, rule := range rules {
					from := rule.ClientIP
					to := IP4fromOffset(rule.DestIPOffset)
					if source == from && destination == to {
						if stats[i].Bytes > rule.BytesUsed {
							rule.BytesUsed = stats[i].Bytes
							rule.Until = time.Now()
							m.db.ExtendFwdRule(&rule, time.Now().Add(time.Second*630))
							break
						}
					}
				}
			}
		}
	}

	now := time.Now()
	for i := range rules {
		if now.After(rules[i].CacheExpiry) {
			err := m.fw.RemoveForwardRule(&rules[i])
			if err == nil {
				m.db.DeleteFwdRule(&rules[i])
			}
		}
	}
}
