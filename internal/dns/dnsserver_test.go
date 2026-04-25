package dns

import (
	"sleuth/internal/firewall"
	"testing"

	"github.com/miekg/dns"
)

func TestProcessDnsQueryLocalA(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("service1.local.", dns.TypeA, "127.0.0.1")
	checkTestInt(t, dns.RcodeSuccess, errCode)
	checkTestInt(t, 2, len(res))
	aRecord1 := res[0].(*dns.A)
	aRecord2 := res[1].(*dns.A)
	checkTestString(t, "192.168.178.1", aRecord1.A.String())
	checkTestString(t, "192.168.179.1", aRecord2.A.String())
}

func TestProcessDnsQueryLocalAAAA(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("service1.local.", dns.TypeAAAA, "127.0.0.1")
	checkTestInt(t, dns.RcodeSuccess, errCode)
	checkTestInt(t, 1, len(res))
	aRecord1 := res[0].(*dns.AAAA)
	checkTestString(t, "fe80::9656:d028:8652:1111", aRecord1.AAAA.String())
}

func TestProcessDnsQueryBlacklist(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("googleads.g.doubleclick.net.", dns.TypeA, "127.0.0.1")
	checkTestInt(t, dns.RcodeNameError, errCode)
	checkTestInt(t, 0, len(res))
}

func TestProcessDnsQueryBlacklistWhitelisted(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("iadsdk.apple.com.", dns.TypeCNAME, "127.0.0.1")
	checkTestInt(t, dns.RcodeSuccess, errCode)
	checkTestInt(t, 1, len(res))
	cnameRecord1 := res[0].(*dns.CNAME)
	checkTestString(t, "iadsdk.apple.com.akadns.net.", cnameRecord1.Target)
}

func TestProcessDnsQueryUpstreamSuccess(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("dns.google.", dns.TypeA, "127.0.0.1")
	checkTestInt(t, dns.RcodeSuccess, errCode)
	checkTestInt(t, 2, len(res))
	aRecord1 := res[0].(*dns.A)
	aRecord2 := res[1].(*dns.A)
	checkTestBool(t, true, aRecord1.A.String() == "8.8.8.8" || aRecord1.A.String() == "8.8.4.4")
	checkTestBool(t, true, aRecord2.A.String() == "8.8.8.8" || aRecord2.A.String() == "8.8.4.4")
	checkTestBool(t, true, aRecord1.A.String() != aRecord2.A.String())
}

func TestProcessDnsQueryUpstreamNonExistent(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("nonexistentrecord.virtualzone.de.", dns.TypeA, "127.0.0.1")
	checkTestInt(t, dns.RcodeNameError, errCode)
	checkTestInt(t, 0, len(res))
}

func TestProcessDnsQueryEmptyName(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery(".", dns.TypeA, "127.0.0.1")
	checkTestInt(t, dns.RcodeNameError, errCode)
	checkTestInt(t, 0, len(res))
}

func TestProcessDnsQueryWildcard(t *testing.T) {
	d := InitDnsServer(firewall.LoadFirewallManager())
	res, errCode := d.processDnsQuery("*.", dns.TypeA, "127.0.0.1")
	checkTestInt(t, dns.RcodeNameError, errCode)
	checkTestInt(t, 0, len(res))
}
