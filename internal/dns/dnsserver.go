package dns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/firewall"
	"sleuth/internal/security"
	"strings"
	"syscall"
	"unsafe"

	"github.com/miekg/dns"
)

type DnsServer struct {
	db       *db.Db
	fw       firewall.FirewallManager
	security security.Security
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

func (s *DnsServer) processDnsResponse(name string, qtype uint16, arr []dns.RR, source string, if_ip string) []dns.RR {
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
					_, reason := s.security.VerifyDomainAccess(source, header.Name)
					if s.fw.IsActive() {
						allocatedIP, err := s.fw.AllocateIPv4(source, header.Name, qtype, arr[i].(*dns.A).A.String(), ttl, reason, if_ip)
						if err != nil {
							fmt.Println(fmt.Errorf("Error allocating IP: %v", err))
						}
						newRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", header.Name, 60 /*ttl*/, getQueryTypeText(header.Rrtype), allocatedIP))
						resp[header.Rrtype] = newRR
					} else {
						resp[header.Rrtype] = arr[i]
					}
				}
			case dns.TypeAAAA:
				fmt.Println(fmt.Errorf("AAAA not yet supported for: %s", header.Name))
			default:
				resp[header.Rrtype] = arr[i]
			}
		}
	}

	values := make([]dns.RR, 0, len(resp))
	for _, v := range resp {
		values = append(values, v)
	}
	s.db.CreateDNSCacheRecord(source, name, qtype, ttl, &values)
	return values
}

func (s *DnsServer) processDnsQuery(name string, qtype uint16, source string, if_ip string) ([]dns.RR, int) {
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

	if name == "my.session." && qtype == 1 { // special case to allow logout
		rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, 60 /*ttl*/, "A", if_ip))
		arr = append(arr, rr)
		return s.processDnsResponse(name, qtype, arr, source, if_ip), dns.RcodeSuccess
	}

	arr, err = queryUpstream(name, qtype)
	if err == nil {
		logQueryResult(source, name, qtype, "resolved via upstream")
		return s.processDnsResponse(name, qtype, arr, source, if_ip), dns.RcodeSuccess
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
		s.parseQuery(w.RemoteAddr(), lastDstIP[w.RemoteAddr().String()], m)
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Fatal(err)
	}
	w.Close()
}

func InitDnsServer(fw firewall.FirewallManager, db *db.Db, security *security.Security) *DnsServer {
	s := &DnsServer{
		fw:       fw,
		db:       db,
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

	//dns.HandleFunc(".", s.handleDnsRequest)

	log.Printf("Starting at %s\n", GetConfig().ListenAddr)
	pc, err := newPktinfoConn(":53") // net.ListenPacket("udp", ":53")
	//err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
	/*rawConn, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		log.Fatal(err)
	}
	err = rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	})
	if err != nil {
		log.Fatal(err)
	}*/

	//myPktinfoConn, err := newPktinfoConn(":53")

	server := &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(s.handleDnsRequest),
		/*Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			var localIP net.IP

			// Extract our custom packetAddr
			if pa, ok := w.RemoteAddr().(*packetAddr); ok {
				localIP = pa.dstIP
			}

			// Wrap the ResponseWriter to override LocalAddr()
			wrapped := &localAddrOverride{
				ResponseWriter: w,
				localAddr: &net.UDPAddr{
					IP:   localIP,
					Port: 53, // DNS port
				},
			}

			s.handleDnsRequest(wrapped, r)

			m := new(dns.Msg)
			m.SetReply(r)
			_ = wrapped.WriteMsg(m)
		}),*/
	}
	defer server.Shutdown()
	//log.Fatal(server.ListenAndServe())
	log.Fatal(server.ActivateAndServe())

}

func (s *DnsServer) ReevaluateDomainAccess(fwr *constants.FwdRule) error {
	_, newReason := s.security.VerifyDomainAccess(fwr.ClientIP, fwr.Hostname)
	if newReason != fwr.ReasonCode {
		return s.fw.UpdateIPv4(fwr, newReason)
	}
	return nil
}

func (s *DnsServer) FlushCache(clientIP string) error {
	return s.db.FlushDNSCacheRecords(clientIP)
}

type pktinfoConn struct {
	*net.UDPConn
}

func newPktinfoConn(addr string) (*pktinfoConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
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

	return &pktinfoConn{conn}, nil
}

// Helper type to pass local IP
type packetAddr struct {
	net.Addr
	dstIP net.IP
}

var lastDstIP map[string]string = make(map[string]string)

func (p *pktinfoConn) ReadFrom(b []byte) (int, net.Addr, error) {
	oob := make([]byte, 1024)
	n, oobn, _, raddr, err := p.UDPConn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, err
	}

	var dstIP net.IP
	cmsgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == syscall.IPPROTO_IP && cmsg.Header.Type == syscall.IP_PKTINFO {
			pktinfo := (*syscall.Inet4Pktinfo)(unsafe.Pointer(&cmsg.Data[0]))
			dstIP = net.IPv4(pktinfo.Addr[0], pktinfo.Addr[1], pktinfo.Addr[2], pktinfo.Addr[3])
		}
	}

	// Return the actual client address
	// Save dstIP somewhere for use in the handler
	lastDstIP[raddr.String()] = strings.Split(dstIP.String(), ":")[0] // simple map keyed by client addr

	return n, raddr, nil
}

type localAddrOverride struct {
	dns.ResponseWriter
	localAddr net.Addr
}

func (l *localAddrOverride) LocalAddr() net.Addr {
	return l.localAddr
}
