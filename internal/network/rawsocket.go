package network

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// rawSocket is a cross-platform raw network socket using pcap
type rawSocket struct {
	handle *pcap.Handle
}

// newRawSocket opens a raw packet interface for a given network adapter
func newRawSocket(intf *net.Interface) (*rawSocket, error) {
	// Open live capture on the interface

	handle, err := pcap.OpenLive(intf.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", intf.Name, err)
	}

	return &rawSocket{
		handle: handle,
	}, nil
}

// Read reads one packet from the interface
func (s *rawSocket) Read() ([]byte, error) {
	data, _, err := s.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Write sends raw bytes to the interface
func (s *rawSocket) Write(data []byte) error {
	return s.handle.WritePacketData(data)
}
