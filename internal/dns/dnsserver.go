package dns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/firewall"
	"sleuth/internal/network"
	"sleuth/internal/security"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

type DnsServer struct {
	db       *db.Db
	fw       firewall.FirewallManager
	network  *network.Network
	security *security.Security
	settings *db.Settings
}

func (s *DnsServer) parseQuery(source net.Addr, interfaceAddress string, m *dns.Msg) {
	for _, q := range m.Question {
		name := strings.ToLower(q.Name)
		res, errCode := s.processDnsQuery(name, q.Qtype, strings.Split(source.String(), ":")[0], interfaceAddress)
		m.Answer = append(m.Answer, res...)
		m.Rcode = errCode
	}
}

func (s *DnsServer) queryCache(clientIP string, name string, qtype uint16) ([]dns.RR, error) {
	if s.db != nil {
		return nil, errors.New("Db not refereced, cache not availabe")
	}
	records := s.db.GetDNSCacheRecord(clientIP, name, qtype)
	if records == nil {
		return nil, fmt.Errorf("%s %s not found in cache", name, getQueryTypeText(qtype))
	}
	return *records, nil
}

func (s *DnsServer) processDnsResponse(name string, qtype uint16, arr []dns.RR, ses security.SessionInfo, if_ip string) []dns.RR {
	resp := make(map[uint16]dns.RR)
	ttl := uint32(32767)
	for i := range arr {
		header := arr[i].Header()
		if header.Ttl < ttl {
			ttl = header.Ttl
		}
		if resp[header.Rrtype] == nil {
			switch header.Rrtype {
			case dns.TypeA:
				{
					ttl := header.Ttl
					qtype := arr[i].Header().Rrtype
					allocatedIP, err := s.fw.AllocateIPv4(ses.ClientIP, name, qtype, arr[i].(*dns.A).A.String(), ttl, ses.RejectReason, if_ip)
					if err != nil {
						fmt.Println(fmt.Errorf("Error allocating IP: %v", err))
					}
					newRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", header.Name, 1 /*ttl*/, getQueryTypeText(header.Rrtype), allocatedIP))
					resp[header.Rrtype] = newRR

				}
			case dns.TypeAAAA:
				fmt.Println(fmt.Errorf("AAAA not yet supported for: %s", header.Name))
			case dns.TypeCNAME:
				resp[header.Rrtype] = arr[i]
			default:
				if ses.RejectReason == 0 {
					resp[header.Rrtype] = arr[i]
				}
			}
		}
	}

	values := make([]dns.RR, 0, len(resp))
	for _, v := range resp {
		values = append(values, v)
	}
	s.db.CreateDNSCacheRecord(ses.ClientIP, name, qtype, ttl, &values)
	return values
}

func (s *DnsServer) queryLocal(name string, qtype uint16) ([]dns.RR, error) {
	localdomain := s.settings.LocalDomain
	if s.db == nil {
		return nil, errors.New("Db access required to query local")
	}
	if s.network == nil {
		return nil, errors.New("Db access required to query local")
	}
	if s.settings == nil {
		return nil, errors.New("Settings access required to query local")
	}
	if localdomain == "" {
		return nil, errors.New("Local domain not specified")
	}
	if localdomain[0] != '.' {
		localdomain = "." + localdomain
	}
	if localdomain[len(localdomain)-1] != '.' {
		localdomain += "."
	}
	if len(name) > len(localdomain) && name[len(name)-len(localdomain):] == localdomain {
		hostname := name[0 : len(name)-len(localdomain)]
		res := make([]dns.RR, 0)

		for _, device := range s.db.GetDevices() {
			if device.DNSName == hostname {
				dev := s.network.FindByMac(device.MACAddress)
				if dev.Ip != nil {
					rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", name, getQueryTypeText(qtype), dev.Ip.String()))
					res = append(res, rr)
					if err != nil {
						log.Println(err)
						return []dns.RR{}, err
					}

				}
			}
		}

		return res, nil
	}
	return nil, errors.New("Not within local domain")

}

func (s *DnsServer) processDnsQuery(name string, qtype uint16, source string, if_ip string) ([]dns.RR, int) {
	arr := make([]dns.RR, 0)

	arr, err := s.queryLocal(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved as local address")
		return arr, dns.RcodeSuccess
	}
	arr, err = s.queryCache(source, name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved from cache")
		return arr, dns.RcodeSuccess
	}

	ses, _ := s.security.GetSessionInfo(source)
	if qtype == 1 && name == "my.session." { // special case to allow logout
		rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, 60, "A", if_ip))
		arr = append(arr, rr)
		return s.processDnsResponse(name, qtype, arr, ses, if_ip), dns.RcodeSuccess
	}

	arr, err = queryBlacklist(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved as blacklisted name")
		return arr, dns.RcodeNameError
	}

	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{
		Name:   name,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}

	c := new(dns.Client)
	fallbackAddress := s.settings.FallbackDNS

	if fallbackAddress == "" {
		fallbackAddress = "1.1.1.1"
	} else {
		if net.ParseIP(fallbackAddress) == nil {
			fallbackAddress = "1.1.1.1"
		}
	}

	if len(strings.Split(fallbackAddress, ":")) < 2 {
		fallbackAddress = fmt.Sprintf("%s:53", fallbackAddress)
	}
	address := fallbackAddress
	if ses.DNS != nil && ses.DNS.Address != "" {
		address = ses.DNS.Address
		switch ses.DNS.Type {
		case 0:
			if len(strings.Split(address, ":")) < 2 {
				address = fmt.Sprintf("%s:53", address)
			}
		case 1:
			c.Net = "tcp"
			if len(strings.Split(address, ":")) < 2 {
				address = fmt.Sprintf("%s:53", address)
			}
			c = &dns.Client{
				Net: "tcp",
				Dialer: &net.Dialer{
					Resolver: &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
							d := net.Dialer{}
							return d.DialContext(ctx, network, fallbackAddress)
						},
					},
				},
			}
		case 2:
			if len(strings.Split(address, ":")) < 2 {
				address = fmt.Sprintf("%s:853", address)
			}
			c = &dns.Client{
				Net: "tcp-tls",
				Dialer: &net.Dialer{
					Resolver: &net.Resolver{
						PreferGo: true,
						Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
							d := net.Dialer{}
							return d.DialContext(ctx, network, fallbackAddress)
						},
					},
				},
			}
		}
	}

	in, _, err := c.Exchange(m1, address)

	if err == nil {
		logQueryResult(source, name, qtype, "resolved via upstream")
		return s.processDnsResponse(name, qtype, in.Answer, ses, if_ip), dns.RcodeSuccess
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
		if w.RemoteAddr() != nil {
			remoteIP := strings.Split(w.RemoteAddr().String(), ":")[0]
			var localIP string
			if val, ok := lastDstIP.Load(remoteIP); ok {
				localIP = val.(string)
			} else {
				localIP = w.RemoteAddr().String()
			}
			s.parseQuery(w.RemoteAddr(), localIP, m)
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Print(err)
	}
	w.Close()
}

func InitDnsServer(fw firewall.FirewallManager, db *db.Db, security *security.Security, network *network.Network, settings *db.Settings) *DnsServer {
	s := &DnsServer{
		fw:       fw,
		db:       db,
		security: security,
		settings: settings,
		network:  network,
	}
	GetConfig().ReadConfig()
	GetConfig().Print()

	initLogging()
	GetUpstreamCache().Init()
	updateLocalRecords()
	//updateBlacklistRecords()
	updateWhitelistRecords()
	//initBlacklistRenewal()
	return s
}

func (s DnsServer) Start() {
	log.Printf("Starting at %s\n", GetConfig().ListenAddr)
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 53,
	}

	udpConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	pc, err := newPktinfoConn(udpConn) // net.ListenPacket("udp", ":53")

	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(s.handleDnsRequest),
	}
	defer server.Shutdown()
	log.Fatal(server.ActivateAndServe())

}

func (s *DnsServer) ReevaluateDomainAccess(fwr *constants.FwdRule) error {
	_, newReason := s.security.VerifyDomainAccess(fwr.ClientIP, fwr.Hostname)
	if newReason != fwr.ReasonCode {
		if s.fw.IsActive() {
			return s.fw.UpdateIPv4(fwr, newReason)
		}
		fwr.ReasonCode = newReason
		return s.db.ExtendFwdRule(fwr, time.Now().Add(time.Duration(330)*time.Second))
	}
	return nil
}

func (s *DnsServer) FlushCache(clientIP string) error {
	return s.db.FlushDNSCacheRecords(clientIP)
}

type pktinfoConn struct {
	*net.UDPConn
	pconn *ipv4.PacketConn
}

func newPktinfoConn(conn *net.UDPConn) (*pktinfoConn, error) {
	p := ipv4.NewPacketConn(conn)

	// Enable control messages for destination IP + interface
	if err := p.SetControlMessage(
		ipv4.FlagDst|ipv4.FlagInterface,
		true,
	); err != nil {
		return nil, err
	}

	return &pktinfoConn{
		UDPConn: conn,
		pconn:   p,
	}, nil

	/*udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// Enable IP_PKTINFO
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	err = rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	})
	if err != nil {
		return nil, err
	}

	return &pktinfoConn{conn}, nil*/
}

var lastDstIP sync.Map // was: var lastDstIP map[string]string = make(map[string]string)

func (p *pktinfoConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, cm, raddr, err := p.pconn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	if cm != nil && cm.Dst != nil {
		host, _, err := net.SplitHostPort(raddr.String())
		if err == nil {
			lastDstIP.Store(host, cm.Dst.String()) // thread-safe
		}
	}

	return n, raddr, nil
}
