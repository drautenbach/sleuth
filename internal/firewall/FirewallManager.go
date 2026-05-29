package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/log"
	"time"

	"github.com/miekg/dns"
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

	//rules := m.db.GetReverseDNS()
	sessions := m.db.GetDNSSessions()
	rules := make([]constants.FwdRule, 0)
	for _, s := range sessions {
		rule := constants.FwdRule{
			ClientIP:    s.ClientIP,
			InterfaceIP: s.InterfaceIP,
			ReasonCode:  s.ReasonCode,
		}
		if s.DNSResponse.A != nil {
			rule.TargetIP = s.DNSResponse.A.IP
			rule.AllocatedIP = s.DNSResponse.A.AllocatedIP
		}
		rules = append(rules, rule)
	}

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
		rules := make([]constants.FwdRule, 0)
		for _, s := range sessions {
			if time.Now().After(s.SessionExpiry) {
				if s.DNSResponse.A != nil {
					m.db.DeleteReverseDNS(s.ClientIP, s.QType, uint16(OffsetFromIP4(s.DNSResponse.A.AllocatedIP)))
				}
				m.db.DeleteDNSSession(&s)
			} else {
				rule := constants.FwdRule{
					ClientIP:    s.ClientIP,
					InterfaceIP: s.InterfaceIP,
					ReasonCode:  s.ReasonCode,
				}
				if s.DNSResponse.A != nil {
					rule.TargetIP = s.DNSResponse.A.IP
					rule.AllocatedIP = s.DNSResponse.A.AllocatedIP
				}
				rules = append(rules, rule)
			}
		}
		m.fw.Init(rules)
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

func OffsetFromIP4(IP string) uint32 {
	ipint, _ := ip4ToInt(IP)
	ipstart, _ := ip4ToInt("10.0.0.1")
	if ipint > ipstart {
		return ipint - ipstart
	}
	return max_value
}

const max_value = 65535 //256*256
func firstAvailable(nums []constants.ReverseDNS) (uint16, bool) {
	var seen [(max_value + 1) / 64]uint64

	// Mark numbers as seen
	for _, n := range nums {
		seen[n.DestIPOffset>>6] |= 1 << (n.DestIPOffset & 63)
	}

	for wordIdx, word := range seen {
		inv := ^word

		if inv != 0 {
			bit := bits.TrailingZeros64(inv)
			result := wordIdx*64 + bit

			if result <= max_value {
				return uint16(result), true
			}
		}
	}

	// All numbers used
	return 0, false
}

func (m *FirewallManager) Allocate(session constants.DNSSession, if_ip string) error {
	var err error

	if session.DNSResponse.A != nil {
		// check if IP is already allocated
		if session.DNSResponse.A.AllocatedIP != "" {
			t := OffsetFromIP4(session.DNSResponse.A.AllocatedIP)
			if t < uint32(max_value) {
				rdns := m.db.GetReverseDNS(session.ClientIP, dns.TypeA, uint16(t))
				if rdns != nil {
					if rdns.Hostname == session.Hostname {
						return nil
					}
					m.db.DeleteReverseDNS(session.ClientIP, dns.TypeA, uint16(t))
				}
			}
		}

		rules := m.db.GetReverseDNSByClientType(session.ClientIP, session.QType)
		destIPOffset, found := firstAvailable(rules)

		if !found {
			return errors.New("no available IP offset")
		} else {
			destIP := IP4fromOffset(destIPOffset)
			err := m.db.CreateReverseDNS(session.ClientIP, session.QType, &constants.ReverseDNS{
				Hostname:     session.Hostname,
				IP:           session.DNSResponse.A.IP,
				DestIP:       destIP,
				DestIPOffset: destIPOffset,
			})
			if err == nil {
				if m.fw != nil {
					m.fw.AddForwardRule(&constants.FwdRule{
						ClientIP:    session.ClientIP,
						InterfaceIP: if_ip,
						HostName:    session.Hostname,
						AllocatedIP: destIP,
						TargetIP:    session.DNSResponse.A.IP,
						ReasonCode:  session.ReasonCode,
					})
					session.DNSResponse.A.AllocatedIP = destIP
				} else if session.ReasonCode == 0 {
					session.DNSResponse.A.AllocatedIP = ""
				} else {
					session.DNSResponse.A.AllocatedIP = if_ip
				}
			} else {
				session.DNSResponse.A.AllocatedIP = if_ip //"0.0.0.0"
			}
		}
	}

	if session.DNSResponse.AAAA != nil {
		log.Errorf("%s AAAA not yet supported", session.DNSResponse.AAAA.Name)
	}

	return err
}

func (m *FirewallManager) UpdateIPv4(s *constants.DNSSession, newReasonCode uint16) error {
	r := &constants.FwdRule{
		ClientIP:    s.ClientIP,
		InterfaceIP: s.InterfaceIP,
		ReasonCode:  s.ReasonCode,
		TargetIP:    s.DNSResponse.A.IP,
		AllocatedIP: s.DNSResponse.A.AllocatedIP,
	}

	err := m.fw.RemoveForwardRule(r)
	if err != nil {
		return err
	}
	s.ReasonCode = newReasonCode
	m.db.UpdateDNSSession(s)
	r.ReasonCode = newReasonCode
	return m.fw.AddForwardRule(r)
}

/*func (m *FirewallManager) IPCacheLookup(clientIP string, name string, qtype uint16) *constants.FwdRule {
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
}*/

func (m *FirewallManager) ReviewFwdRules() {
	rules := m.db.GetDNSSessions()

	if m.fw != nil {
		if stats, err := m.fw.GetStats(); err == nil {
			for i := range stats {
				source := stats[i].Source.IP.String()
				destination := stats[i].Destination.IP.String()
				if stats[i].Bytes > 0 {
					for _, rule := range rules {
						if rule.DNSResponse.A != nil {
							from := rule.ClientIP
							to := rule.DNSResponse.A.AllocatedIP
							//to := IP4fromOffset(rule.DestIPOffset)
							if source == from && destination == to {
								if stats[i].Bytes > rule.BytesUsed {
									rule.BytesUsed = stats[i].Bytes
									rule.LastEvent = time.Now()
									rule.SessionExpiry = time.Now().Add(time.Second * 630)
									m.db.UpdateDNSSession(&rule)
									//m.db.ExtendFwdRule(&rule, time.Now().Add(time.Second*630))
									break
								}
							}
						}
					}
				}
			}
		}
	}
	now := time.Now()
	for i := range rules {
		if now.After(rules[i].SessionExpiry) {
			var err error
			if m.fw != nil {
				//err = m.fw.RemoveForwardRule(&rules[i])
				if rules[i].DNSResponse.A != nil {
					err = m.fw.RemoveForwardRule(&constants.FwdRule{
						ClientIP:    rules[i].ClientIP,
						InterfaceIP: rules[i].InterfaceIP,
						ReasonCode:  rules[i].ReasonCode,
						TargetIP:    rules[i].DNSResponse.A.IP,
						AllocatedIP: rules[i].DNSResponse.A.AllocatedIP,
					})
				}
			}
			if err == nil {
				m.db.DeleteDNSSession(&rules[i])
			}
		}
	}

}

func (m *FirewallManager) FlushSource(clientIP string) {
	rules := m.db.GetDNSSessionsForClient(clientIP)
	for i := range rules {
		if m.fw != nil {
			if rules[i].DNSResponse.A != nil {
				m.fw.RemoveForwardRule(&constants.FwdRule{
					ClientIP:    rules[i].ClientIP,
					InterfaceIP: rules[i].InterfaceIP,
					ReasonCode:  rules[i].ReasonCode,
					TargetIP:    rules[i].DNSResponse.A.IP,
					AllocatedIP: rules[i].DNSResponse.A.AllocatedIP,
				})
			}
		}
		m.db.DeleteDNSSession(&rules[i])
	}
	for _, ip := range m.db.GetReverseDNSByClientType(clientIP, 1) {
		m.db.DeleteReverseDNS(clientIP, 1, ip.DestIPOffset)
	}
}

func (m *FirewallManager) ExtendFwdRule(clientIP string, hostname string, qtype uint16) error {
	rule := m.db.GetDNSSession(clientIP, hostname, qtype)
	if rule != nil {
		rule.SessionExpiry = time.Now().Add(time.Duration(330) * time.Second)
		return m.db.UpdateDNSSession(rule)
	}
	return fmt.Errorf("Forward rule does not exist %s:%s:%d", clientIP, hostname, qtype)
}
