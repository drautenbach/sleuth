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

func (s *DnsServer) queryCache(clientIP string, name string, qtype uint16) (*constants.DNSSession, error) {
	if s.db == nil {
		return nil, errors.New("Db not refereced, cache not availabe")
	}
	cache := s.db.GetDNSSession(clientIP, name, qtype)
	if cache == nil {
		return nil, fmt.Errorf("%s %s not found in cache", name, getQueryTypeText(qtype))
	}
	return cache, nil
}

func (s *DnsServer) processResponse(name string, qtype uint16, upstream *[]dns.RR, cache *constants.DNSSession, ses security.SessionInfo, if_ip string, isLocal bool) []dns.RR {
	ttl := uint32(32768)
	cached := cache != nil
	if upstream != nil && cached {
		a := make(map[string]constants.DNS_IP_Record)
		aaaa := make(map[string]constants.DNS_IP_Record)
		cache.DNSResponse.Raw = make([]string, 0)
		for _, r := range *upstream {
			ttl = min(ttl, r.Header().Ttl)
			switch r.Header().Rrtype {
			case dns.TypeA:
				a[r.(*dns.A).A.String()] = constants.DNS_IP_Record{
					Name:  r.Header().Name,
					TTL:   r.Header().Ttl,
					Class: dns.ClassToString[r.Header().Class],
					IP:    r.(*dns.A).A.String(),
				}
			case dns.TypeAAAA:
				aaaa[r.(*dns.AAAA).AAAA.String()] = constants.DNS_IP_Record{
					Name:  r.Header().Name,
					TTL:   r.Header().Ttl,
					Class: dns.ClassToString[r.Header().Class],
					IP:    r.(*dns.AAAA).AAAA.String(),
				}
			default:
				cache.DNSResponse.Raw = append(cache.DNSResponse.Raw, r.String())
			}
		}

		matched := false
		if cache.DNSResponse.A != nil {
			_, matched = a[cache.DNSResponse.A.IP]
		}
		if !matched {
			if cache.DNSResponse.A == nil {
				cache.DNSResponse.A = nil
			} else {
				for _, _a := range a {
					cache.DNSResponse.A = &_a
					break
				}
			}
		}
		matched = false
		if cache.DNSResponse.AAAA != nil {
			_, matched = aaaa[cache.DNSResponse.AAAA.IP]
		}
		if !matched {
			if cache.DNSResponse.AAAA == nil {
				cache.DNSResponse.AAAA = nil
			} else {
				for _, _aaaa := range aaaa {
					cache.DNSResponse.A = &_aaaa
					break
				}
			}
		}
		cache.ReasonCode = ses.RejectReason
		cache.DNSExpiry = time.Now().Add(time.Duration(ttl) * time.Second)
		cache.SessionExpiry = time.Now().Add(time.Duration(330) * time.Second)

	} else if cache == nil {
		cache = &constants.DNSSession{
			Since:         time.Now(),
			ClientIP:      ses.ClientIP,
			InterfaceIP:   if_ip,
			Hostname:      name,
			QType:         qtype,
			LastEvent:     time.Now(),
			BytesUsed:     0,
			SessionExpiry: time.Now().Add(time.Duration(330) * time.Second),
			ReasonCode:    ses.RejectReason,
			IsLocal:       isLocal,
			DNSResponse: constants.DNSResponse{
				Raw: make([]string, 0),
			},
		}
		for _, r := range *upstream {
			ttl = min(ttl, r.Header().Ttl)
			switch r.Header().Rrtype {
			case dns.TypeA:
				if cache.DNSResponse.A == nil {
					cache.DNSResponse.A = &constants.DNS_IP_Record{
						Name:  r.Header().Name,
						TTL:   r.Header().Ttl,
						Class: dns.ClassToString[r.Header().Class],
						IP:    r.(*dns.A).A.String(),
					}
				}
			case dns.TypeAAAA:
				if cache.DNSResponse.AAAA == nil {
					cache.DNSResponse.AAAA = &constants.DNS_IP_Record{
						Name:  r.Header().Name,
						TTL:   r.Header().Ttl,
						Class: dns.ClassToString[r.Header().Class],
						IP:    r.(*dns.AAAA).AAAA.String(),
					}
				}
			default:
				cache.DNSResponse.Raw = append(cache.DNSResponse.Raw, r.String())
			}
		}
		cache.DNSExpiry = time.Now().Add(time.Duration(ttl) * time.Second)
	}

	security.VerifyDomainAccess(ses, cache)
	if ses.RejectReason == 0 && cache.ReasonCode == 0 && upstream != nil {
		s.fw.Allocate(*cache, if_ip)
	}

	if cached {
		s.db.UpdateDNSSession(cache)
	} else {
		s.db.CreateDNSSession(cache)
	}

	resp := make([]dns.RR, 0)
	for _, str := range cache.DNSResponse.Raw {
		r, err := dns.NewRR(str)
		if err == nil {
			resp = append(resp, r)
		}
	}
	if cache.DNSResponse.A != nil {
		ip := cache.DNSResponse.A.IP
		if ses.RejectReason > 0 || cache.ReasonCode > 0 {
			ip = if_ip
		} else if ses.DynamicRouting && !cache.IsLocal && cache.DNSResponse.A.AllocatedIP != "" {
			ip = cache.DNSResponse.A.AllocatedIP
		}
		resp = append(resp, &dns.A{
			Hdr: dns.RR_Header{
				Name:   cache.DNSResponse.A.Name,
				Class:  dns.StringToClass[cache.DNSResponse.A.Class],
				Ttl:    1,
				Rrtype: dns.TypeA,
			},
			A: net.ParseIP(ip).To4(),
		})
	}
	return resp
}

func (s *DnsServer) queryLocal(name string, qtype uint16, source string, if_ip string) ([]dns.RR, error) {
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

	hostname := ""
	if len(name) > len(localdomain) && name[len(name)-len(localdomain):] == localdomain {
		hostname = name[0 : len(name)-len(localdomain)]
	} else if len(strings.Split(name, ".")) == 2 {
		hostname = strings.Split(name, ".")[0]
	}

	if hostname != "" {
		arr := make([]dns.RR, 0)

		if hostname == "session" {
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, 1, getQueryTypeText(qtype), if_ip))
			arr = append(arr, rr)
			if err != nil {
				log.Println(err)
				return []dns.RR{}, err
			}
		} else {
			for _, device := range s.db.GetDevices() {
				if device.DNSName == hostname {
					dev := s.network.FindByMac(device.MACAddress)
					if dev != nil && dev.Ip != nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, 1, getQueryTypeText(qtype), dev.Ip.String()))
						arr = append(arr, rr)
						if err != nil {
							log.Println(err)
							return []dns.RR{}, err
						}
					}
				}
			}
		}

		if len(arr) > 0 {
			//s.security.VerifySessionAccess(source)
			return arr, nil
		}

	}
	return nil, errors.New("Not within local domain")

}

func (s *DnsServer) queryUpstream(name string, qtype uint16, source string, if_ip string, config *db.DNSConfiguration) ([]dns.RR, error) {
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
	if config != nil && config.Address != "" {
		address = config.Address
		switch config.Type {
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
	return in.Answer, err
}

func (s *DnsServer) processDnsQuery(name string, qtype uint16, source string, if_ip string) ([]dns.RR, int) {
	arr := make([]dns.RR, 0)

	ses, _ := s.security.GetSessionInfo(source)
	if ses.Reevaluate {
		s.ReevaluateAccess(source)
	}
	cache, err := s.queryCache(source, name, qtype)
	if err == nil && cache != nil {
		if time.Until(cache.DNSExpiry) > 0 {
			logQueryResult(source, name, qtype, "resolved from cache")
			return s.processResponse(name, qtype, nil, cache, ses, if_ip, cache.IsLocal), dns.RcodeSuccess
		}
	}

	arr, err = s.queryLocal(name, qtype, source, if_ip)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved as local address")
		//return arr, dns.RcodeSuccess
		return s.processResponse(name, qtype, &arr, cache, ses, if_ip, true), dns.RcodeSuccess
	}

	/*arr, err = queryBlacklist(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved as blacklisted name")
		return arr, dns.RcodeNameError
	}*/

	arr, err = s.queryUpstream(name, qtype, source, if_ip, ses.DNS)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved via upstream")
		return s.processResponse(name, qtype, &arr, cache, ses, if_ip, false), dns.RcodeSuccess
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

func (s *DnsServer) ReevaluateAccess(clientIP string) {
	_, newReason := s.security.VerifySessionAccess(clientIP)
	allrules := s.db.GetDNSSessionsForClient(clientIP)
	for i := range allrules {
		//if allrules[i].ReasonCode == 0 {
		if newReason != allrules[i].ReasonCode {
			if s.fw.IsActive() && allrules[i].DNSResponse.A != nil {
				s.fw.UpdateIPv4(&allrules[i], newReason)
			}
			allrules[i].ReasonCode = newReason
			allrules[i].SessionExpiry = time.Now().Add(time.Duration(330) * time.Second)
			s.db.UpdateDNSSession(&allrules[i])
		}

		//}
	}
}

func (s *DnsServer) FlushCache(clientIP string) error {
	return s.db.FlushDNSSessions(clientIP)
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
