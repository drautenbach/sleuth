//go:build linux
// +build linux

package firewall

import (
	"strconv"

	"github.com/coreos/go-iptables/iptables"
)

type iptManager struct {
	ipt *iptables.IPTables
}

func NewIptablesManager() (FirewallManager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &iptManager{ipt: ipt}, nil
}

func (m *iptManager) AddAllowPort(protocol string, port int) error {
	return m.ipt.AppendUnique("filter", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (m *iptManager) RemoveAllowPort(protocol string, port int) error {
	return m.ipt.Delete("filter", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (m *iptManager) Flush() error {
	// best-effort: delete rules we added is safer; here we do nothing.
	return nil
}

func (m *iptManager) Close() error {
	return nil
}
