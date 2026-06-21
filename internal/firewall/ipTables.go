//go:build linux
// +build linux

package firewall

import (
	"fmt"
	"os"
	"sleuth/internal/constants"
	"sleuth/internal/log"
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
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

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
		if r.AllocatedIP != "" {
			m.AddForwardRule(&r)
		}
	}

	return nil
}

func (m *ipTables) Close(fwdrules []constants.FwdRule) error {
	return nil
}

func getDestIP(fwdrule *constants.FwdRule) (string, string) {
	chain := "PREROUTING"
	if fwdrule.InterfaceIP == fwdrule.ClientIP {
		chain = "OUTPUT"
	}
	if fwdrule.ReasonCode > 0 { // Block access due to reasoncode
		return fwdrule.InterfaceIP, chain
	}
	return fwdrule.TargetIP, chain
}

func (m *ipTables) AddForwardRule(fwdrule *constants.FwdRule) error {
	/*err := m.ipt.Append("nat", "PREROUTING", "-s", fwdrule.ClientIP, "-d", IP4fromOffset(fwdrule.DestIPOffset), "-j", "DNAT", "--to-destination", fwdrule.OrigIP)
	if err != nil {
		fmt.Println(fmt.Errorf("Error appending PREROUTING DNAT rule: %v", err))
	}*/

	destIP, chain := getDestIP(fwdrule)

	if fwdrule.ClientIP == fwdrule.AllocatedIP {
		log.Errorf("unexpected IP allocation %s", fwdrule.ClientIP)
	} else {
		err := m.ipt.Append("nat", chain, "-s", fwdrule.ClientIP, "-d", fwdrule.AllocatedIP, "-j", "DNAT", "--to-destination", destIP)
		if err != nil {
			fmt.Printf("Error appending %s, DNAT rule %s -> %s -> %s, %v\n", chain, fwdrule.HostName, fwdrule.AllocatedIP, destIP, err)
			return err
		} else {
			fmt.Printf("Created %s Rule %s, %s: %s -> %s\n", chain, fwdrule.ClientIP, fwdrule.HostName, fwdrule.AllocatedIP, destIP)
		}
		if chain == "PREROUTING" {
			m.ipt.AppendUnique("filter", "FORWARD", "-s", fwdrule.ClientIP, "-j", "ACCEPT")
			m.ipt.AppendUnique("filter", "FORWARD", "-d", fwdrule.ClientIP, "-j", "ACCEPT")
		}
	}

	return nil
}

func (m *ipTables) RemoveForwardRule(fwdrule *constants.FwdRule) error {
	/*err := m.ipt.Delete("nat", "PREROUTING", "-s", fwdrule.ClientIP, "-d", IP4fromOffset(fwdrule.DestIPOffset), "-j", "DNAT", "--to-destination", fwdrule.OrigIP)
	if err != nil {
		fmt.Println(fmt.Errorf("Error deleting PREROUTING DNAT rule: %v", err))
		return err
	}*/
	destIP, chain := getDestIP(fwdrule)
	err := m.ipt.Delete("nat", chain, "-s", fwdrule.ClientIP, "-d", fwdrule.AllocatedIP, "-j", "DNAT", "--to-destination", destIP)
	if err != nil {
		fmt.Printf("Error deleting %s rule %s -> %s -> %v\n", fwdrule.HostName, fwdrule.AllocatedIP, destIP, err)
		return err
	} else {
		fmt.Printf("Deleted %s Rule %s, %s: %s -> %s\n", chain, fwdrule.ClientIP, fwdrule.HostName, fwdrule.AllocatedIP, destIP)
	}

	/*err = m.ipt.Delete("filter", "FORWARD", "-d", fwdrule.OrigIP, "-j", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error deleting FORWARD rule for destination: %v", err))
		return err
	}
	err = m.ipt.Delete("filter", "FORWARD", "-s", fwdrule.OrigIP, "-j", "ACCEPT")
	if err != nil {
		fmt.Println(fmt.Errorf("Error deleting FORWARD rule for source: %v", err))
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
