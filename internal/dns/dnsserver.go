package dns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sleuth/internal/constants"
	"sleuth/internal/firewall"
	"sleuth/internal/network"
	"sleuth/internal/security"
	"strings"

	"github.com/miekg/dns"
)

type DnsServer struct {
	fw       firewall.FirewallManager
	security security.Security
}

func (s *DnsServer) parseQuery(source net.Addr, m *dns.Msg) {
	for _, q := range m.Question {
		name := strings.ToLower(q.Name)
		res, errCode := s.processDnsQuery(name, q.Qtype, strings.Split(source.String(), ":")[0])
		m.Answer = append(m.Answer, res...)
		m.Rcode = errCode
	}
}

func (s *DnsServer) queryCache(clientIP string, name string, qtype uint16) ([]dns.RR, error) {
	fr := s.fw.IPCacheLookup(clientIP, name, qtype)
	if fr == nil {
		return nil, errors.New("Forward rule does not exist")
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN %s %s", name, getQueryTypeText(fr.QType), firewall.IP4fromOffset(fr.DestIPOffset)))
	return []dns.RR{rr}, err
}

func (s *DnsServer) processDnsResponse(arr []dns.RR, source string) []dns.RR {
	if s.fw.IsActive() {
		resp := make(map[uint16]dns.RR)
		for i := range arr {
			header := arr[i].Header()
			if resp[header.Rrtype] == nil {
				actualIP := ""
				switch header.Rrtype {
				case dns.TypeA:
					actualIP = arr[i].(*dns.A).A.String()
				default:
					fmt.Printf("Did not process dns type %s %s", getQueryTypeText(header.Rrtype), header)
				}
				if actualIP != "" {
					ttl := header.Ttl
					qtype := arr[i].Header().Rrtype
					_, reason := s.security.VerifyDomainAccess(source, header.Name)
					allocatedIP, err := s.fw.AllocateIPv4(source, header.Name, qtype, actualIP, ttl, reason)
					if err != nil {
						fmt.Println(fmt.Errorf("Error allocating IP: %v", err))
					}
					newRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", header.Name, 60 /*ttl*/, getQueryTypeText(header.Rrtype), allocatedIP))
					resp[header.Rrtype] = newRR
				} else {
					resp[header.Rrtype] = arr[i]
				}
			}
		}

		values := make([]dns.RR, 0, len(resp))
		for _, v := range resp {
			values = append(values, v)
		}
		return values

	}

	return arr
}

func (s *DnsServer) processDnsQuery(name string, qtype uint16, source string) ([]dns.RR, int) {
	arr := make([]dns.RR, 0)

	arr, err := queryLocal(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved as local address")
		return arr, dns.RcodeSuccess
	}
	arr, err = s.queryCache(source, name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved from cache")
		return arr, dns.RcodeSuccess
	}
	arr, err = queryBlacklist(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved as blacklisted name")
		return arr, dns.RcodeNameError
	}

	if name == "cp.local." && qtype == 1 { // special case to allow logout
		ip, _ := network.GetInterfaceIP(source)
		allocatedIP, _ := s.fw.AllocateIPv4(source, name, qtype, ip, 60, constants.AccessAllowed)
		rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, 60 /*ttl*/, "A", allocatedIP))
		arr = append(arr, rr)
		return arr, dns.RcodeSuccess
	}

	arr, err = queryUpstream(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved via upstream")
		return s.processDnsResponse(arr, source), dns.RcodeSuccess
	}
	logQueryResult(source, name, qtype, "did not resolve")
	return []dns.RR{}, dns.RcodeNameError
}

func (s *DnsServer) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		s.parseQuery(w.RemoteAddr(), m)
	}

	w.WriteMsg(m)
	w.Close()
}

func InitDnsServer(fw firewall.FirewallManager, security *security.Security) *DnsServer {
	s := &DnsServer{
		fw:       fw,
		security: *security,
	}
	GetConfig().ReadConfig()
	GetConfig().Print()

	initLogging()
	GetUpstreamCache().Init()
	updateLocalRecords()
	updateBlacklistRecords()
	updateWhitelistRecords()
	initBlacklistRenewal()
	return s
}

func (s DnsServer) Start() {

	dns.HandleFunc(".", s.handleDnsRequest)

	server := &dns.Server{
		Addr: GetConfig().ListenAddr,
		Net:  "udp",
	}
	log.Printf("Starting at %s\n", GetConfig().ListenAddr)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func (s *DnsServer) ReevaluateDomainAccess(fwr *constants.FwdRule) error {
	_, newReason := s.security.VerifyDomainAccess(fwr.ClientIP, fwr.Hostname)
	if newReason != fwr.ReasonCode {
		return s.fw.UpdateIPv4(fwr, newReason)
	}
	return nil
}
