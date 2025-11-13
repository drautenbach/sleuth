package network

import "net"

type Network struct {
	Adapters []net.Interface
}

func InitNetwork() *Network {
	n := &Network{}
	n.RefreshInterfaces()
	return n
}

func (n *Network) RefreshInterfaces() {
	iface, err := net.Interfaces()
	if err == nil {
		n.Adapters = iface
	}

}
