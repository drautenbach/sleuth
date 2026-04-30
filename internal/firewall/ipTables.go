//go:build linux
// +build linux

package firewall

import (
	"fmt"
	"sleuth/internal/constants"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
)

type ipTables struct {
	ipt *iptables.IPTables
}

func NewIptablesManager() (Firewall, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &ipTables{ipt: ipt}, nil
}

func (m *ipTables) Name() string {
	return "iptables"
}

func (m *ipTables) Init(fwdrules []constants.FwdRule) error {
	// Flush the NAT table
	err := m.ipt.ClearChain("nat", "PREROUTING")
	if err != nil {
		fmt.Printf("Error flushing PREROUTING chain: %v\n", err)
	}

	err = m.ipt.ClearChain("nat", "POSTROUTING")
	if err != nil {
		fmt.Printf("Error flushing POSTROUTING chain: %v\n", err)
	}

	err = m.ipt.ClearChain("nat", "INPUT")
	if err != nil {
		fmt.Printf("Error flushing INPUT chain: %v\n", err)
	}

	err = m.ipt.ClearChain("nat", "OUTPUT")
	if err != nil {
		fmt.Printf("Error flushing OUTPUT chain: %v\n", err)
	}

	// Set the default FORWARD policy to ACCEPT
	err = m.ipt.ChangePolicy("filter", "FORWARD", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error setting FORWARD policy: %v", err))
	} else {
		fmt.Println("Set default FORWARD policy to ACCEPT")
	}
	err = m.ipt.Append("nat", "POSTROUTING", "-j", "MASQUERADE")
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending POSTROUTING MASQUERADE rule: %v", err))
	} else {
		fmt.Println("Appended POSTROUTING MASQUERADE rule")
	}

	for _, r := range fwdrules {
		m.AddForwardRule(&r)
	}

	return nil
}

func (m *ipTables) Close(fwdrules []constants.FwdRule) error {
	return nil
}

func (m *ipTables) AddForwardRule(fwdrule *constants.FwdRule) error {
	/*err := m.ipt.Append("nat", "PREROUTING", "-s", fwdrule.ClientIP, "-d", IP4fromOffset(fwdrule.DestIPOffset), "-j", "DNAT", "--to-destination", fwdrule.OrigIP)
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending PREROUTING DNAT rule: %v", err))
	}*/
	err := m.ipt.Append("nat", "OUTPUT", "-s", fwdrule.ClientIP, "-d", IP4fromOffset(fwdrule.DestIPOffset), "-j", "DNAT", "--to-destination", fwdrule.OrigIP)
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending OUTPUT DNAT rule: %v", err))
	}

	/*err = m.ipt.Append("filter", "FORWARD", "-d", fwdrule.OrigIP, "-j", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending FORWARD rule for destination: %v", err))
	}
	err = m.ipt.Append("filter", "FORWARD", "-s", fwdrule.OrigIP, "-j", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending FORWARD rule for source: %v", err))
	}*/

	return nil
}

func (m *ipTables) RemoveForwardRule(fwdrule *constants.FwdRule) error {
	/*err := m.ipt.Delete("nat", "PREROUTING", "-s", fwdrule.ClientIP, "-d", IP4fromOffset(fwdrule.DestIPOffset), "-j", "DNAT", "--to-destination", fwdrule.OrigIP)
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending PREROUTING DNAT rule: %v", err))
		return err
	}*/
	err := m.ipt.Delete("nat", "OUTPUT", "-s", fwdrule.ClientIP, "-d", IP4fromOffset(fwdrule.DestIPOffset), "-j", "DNAT", "--to-destination", fwdrule.OrigIP)
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending OUTPUT DNAT rule: %v", err))
		return err
	}

	/*err = m.ipt.Delete("filter", "FORWARD", "-d", fwdrule.OrigIP, "-j", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending FORWARD rule for destination: %v", err))
		return err
	}
	err = m.ipt.Delete("filter", "FORWARD", "-s", fwdrule.OrigIP, "-j", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending FORWARD rule for source: %v", err))
		return err
	}*/

	return nil
}

func (m *ipTables) GetStats() ([]Stat, error) {
	stats, _ := m.ipt.StructuredStats("nat", "OUTPUT")
	output := make([]Stat, 0)
	for _, stat := range stats {
		output = append(output, Stat{
			Source:      *stat.Source,
			Destination: *stat.Destination,
			Bytes:       stat.Bytes,
		})
	}
	return output, nil
}

func (m *ipTables) AddAllowPort(protocol string, port int) error {
	return m.ipt.AppendUnique("filter", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (m *ipTables) RemoveAllowPort(protocol string, port int) error {
	return m.ipt.Delete("filter", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (m *ipTables) Flush() error {
	// best-effort: delete rules we added is safer; here we do nothing.
	return nil
}
