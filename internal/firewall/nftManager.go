//go:build linux
// +build linux

package firewall

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type nftManager struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
}

func NewNftablesManager() (FirewallManager, error) {
	c := &nftables.Conn{}
	// use a dedicated table for the app
	tbl := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "sleuth_fw",
	})
	// input chain hooked to input with policy accept (we'll add accept rules)
	policy := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{
		Table:    tbl,
		Name:     "input",
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	if err := c.Flush(); err != nil {
		return nil, err
	}
	return &nftManager{conn: c, table: tbl, chain: ch}, nil
}

func protoNum(proto string) (uint8, error) {
	switch proto {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func (m *nftManager) AddAllowPort(protocol string, port int) error {
	pnum, err := protoNum(protocol)
	if err != nil {
		return err
	}
	// payload expr to match L4 proto and dport, then accept
	dport := make([]byte, 2)
	binary.BigEndian.PutUint16(dport, uint16(port))

	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(pnum)}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // destination port offset in transport header
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dport},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}

	m.conn.AddRule(&nftables.Rule{
		Table: m.table,
		Chain: m.chain,
		Exprs: exprs,
	})
	return m.conn.Flush()
}

func (m *nftManager) RemoveAllowPort(protocol string, port int) error {
	// For brevity: simplest approach is to flush table and let caller re-add needed rules.
	// Implementing precise rule deletion requires scanning m.conn.GetRules and matching exprs.
	return fmt.Errorf("RemoveAllowPort not implemented for nftables backend")
}

func (m *nftManager) Flush() error {
	// remove table (best-effort)
	if m.conn == nil || m.table == nil {
		return nil
	}
	m.conn.DelTable(m.table)
	return m.conn.Flush()
}

func (m *nftManager) Close() error {
	return m.Flush()
}
