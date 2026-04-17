//go:build linux
// +build linux

package firewall

import (
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
	return nil
}

func (m *ipTables) Close(fwdrules []constants.FwdRule) error {
	return nil
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
