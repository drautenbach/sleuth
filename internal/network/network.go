package network

import (
	"bytes"
	"log"
	"net"
	"time"
)

// / https://github.com/aler9/landiscover
type Network struct {
	Adapters []net.Interface

	passiveMode bool
	intf        *net.Interface
	ownIP       net.IP
	ls          *listener
	ma          *methodArp
	mm          *methodMdns
	mn          *methodNbns

	arp       chan arpReq
	dns       chan dnsReq
	mdns      chan mdnsReq
	nbns      chan nbnsReq
	terminate chan struct{}

	Nodes map[nodeKey]*node
}

type ArpTable map[string]string

type node struct {
	LastSeen time.Time
	Mac      net.HardwareAddr
	Ip       net.IP
	Dns      string
	Nbns     string
	Mdns     string
}

type nodeKey struct {
	mac [6]byte
	ip  [4]byte
}

func newNodeKey(mac []byte, ip []byte) nodeKey {
	key := nodeKey{}
	copy(key.mac[:], mac)
	copy(key.ip[:], ip)
	return key
}

type arpReq struct {
	srcMac net.HardwareAddr
	srcIP  net.IP
}

type dnsReq struct {
	key nodeKey
	dns string
}

type mdnsReq struct {
	srcMac     net.HardwareAddr
	srcIP      net.IP
	domainName string
}

type nbnsReq struct {
	srcMac net.HardwareAddr
	srcIP  net.IP
	name   string
}

var (
	stop     = make(chan struct{})
	arpCache = &cache{
		table: make(ArpTable),
	}
)

func InitNetwork() *Network {
	layerNbnsInit()
	layerMdnsInit()

	intfName, err := func() (string, error) {
		return defaultInterfaceName()
	}()

	intf := func() *net.Interface {
		if err != nil {
			return nil
		}
		res, err2 := net.InterfaceByName(intfName)
		if err2 != nil {
			return nil
		}
		return res
	}()

	ownIP := func() net.IP {
		addrs, err2 := intf.Addrs()
		if err2 != nil {
			return nil
		}

		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil {
					if bytes.Equal(ipn.Mask, []byte{255, 255, 255, 0}) {
						return ip4
					}
				}
			}
		}
		return nil
	}()

	n := &Network{
		passiveMode: true,
		ownIP:       ownIP,
		intf:        intf,
		arp:         make(chan arpReq),
		dns:         make(chan dnsReq),
		mdns:        make(chan mdnsReq),
		nbns:        make(chan nbnsReq),
		terminate:   make(chan struct{}),

		Nodes: make(map[nodeKey]*node),
	}

	go n.run()

	return n
}

func (n *Network) RefreshInterfaces() {
	iface, err := net.Interfaces()
	if err == nil {
		n.Adapters = iface
	}

}

func AutoRefresh(t time.Duration) {
	go func() {
		for {
			select {
			case <-time.After(t):
				arpCache.Refresh()
			case <-stop:
				return
			}
		}
	}()
}

func StopAutoRefresh() {
	stop <- struct{}{}
}

func CacheUpdate() {
	arpCache.Refresh()
}

func CacheLastUpdate() time.Time {
	return arpCache.Updated
}

func CacheUpdateCount() int {
	return arpCache.UpdatedCount
}

// Search looks up the MAC address for an IP address
// in the arp table
func Search(ip string) string {
	return arpCache.Search(ip)
}

func (n *Network) run() {
	err := newListener(n)
	if err != nil {
		log.Printf("Unable to start socket capture (host name lookup will be disabled): %s", err.Error())
		return
	}
	err = newMethodArp(n)
	if err != nil {
		log.Printf("Unable to initilize arp listener: %s", err.Error())
		return
	}

	err = newMethodMdns(n)
	if err != nil {
		log.Printf("Unable to initilize Mdns listener: %s", err.Error())
		return
	}

	err = newMethodNbns(n)
	if err != nil {
		log.Printf("Unable to initilize Nbns listener: %s", err.Error())
		return
	}

	go n.ls.run()
	go n.ma.run()
	go n.mm.run()
	go n.mn.run()

outer:
	for {
		select {
		case req := <-n.arp:
			key := newNodeKey(req.srcMac, req.srcIP)

			if _, ok := n.Nodes[key]; !ok {
				n.Nodes[key] = &node{
					LastSeen: time.Now(),
					Mac:      req.srcMac,
					Ip:       req.srcIP,
				}

				if !n.passiveMode {
					go n.dnsRequest(key, req.srcIP)
					go n.mm.request(req.srcIP)
					go n.mn.request(req.srcIP)
				}

				// update last seen
			} else {
				n.Nodes[key].LastSeen = time.Now()
			}

		case req := <-n.dns:
			n.Nodes[req.key].Dns = req.dns

		case req := <-n.mdns:
			key := newNodeKey(req.srcMac, req.srcIP)

			if _, ok := n.Nodes[key]; !ok {
				n.Nodes[key] = &node{
					LastSeen: time.Now(),
					Mac:      req.srcMac,
					Ip:       req.srcIP,
				}
			}

			n.Nodes[key].LastSeen = time.Now()
			if n.Nodes[key].Mdns != req.domainName {
				n.Nodes[key].Mdns = req.domainName
			}

		case req := <-n.nbns:
			key := newNodeKey(req.srcMac, req.srcIP)

			if _, has := n.Nodes[key]; !has {
				n.Nodes[key] = &node{
					LastSeen: time.Now(),
					Mac:      req.srcMac,
					Ip:       req.srcIP,
				}
			}

			n.Nodes[key].LastSeen = time.Now()
			if n.Nodes[key].Nbns != req.name {
				n.Nodes[key].Nbns = req.name
			}

		case <-n.terminate:
			break outer
		}

		go func() {
			for {
				select {
				case _, ok := <-n.arp:
					if !ok {
						return
					}
				case <-n.terminate:
					return
				}
			}
		}()
	}
}

func (n *Network) Find(ip string) *node {
	for _, node := range n.Nodes {
		if node.Ip.String() == ip {
			return node
		}
	}
	return nil
}
