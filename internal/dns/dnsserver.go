package dns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sleuth/internal/firewall"
	"strings"

	"github.com/miekg/dns"
)

type DnsServer struct {
	fw firewall.FirewallManager
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
		resp := []dns.RR{}
		ip4_found := false

		for _, rr := range arr {
			if rr.Header().Rrtype == dns.TypeA {
				if !ip4_found {
					a := rr.(*dns.A)
					actualIP := a.A.String()
					ttl := rr.Header().Ttl
					qtype := rr.Header().Rrtype
					allocatedIP, err := s.fw.AllocateIPv4(source, rr.Header().Name, qtype, actualIP, ttl)
					if err != nil {
						// Handle error, perhaps skip or log
						fmt.Println(fmt.Errorf("Error allocating IP: %v", err))
					}
					newRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", rr.Header().Name, ttl, allocatedIP))
					resp = append(resp, newRR)
					ip4_found = true
				}
			} else {
				resp = append(resp, rr)
			}
		}

		return resp

	}

	return arr
}

func (s *DnsServer) processDnsQuery(name string, qtype uint16, source string) ([]dns.RR, int) {
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

func InitDnsServer(fw firewall.FirewallManager) *DnsServer {
	s := &DnsServer{
		fw: fw,
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
