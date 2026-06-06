package network

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// rawSocket is a cross-platform raw network socket using pcap
type rawSocket struct {
	mu sync.Mutex

	intfName string
	handle   *pcap.Handle
}

// newRawSocket opens a raw packet interface for a given network adapter
func newRawSocket(intf *net.Interface) (*rawSocket, error) {
	s := &rawSocket{
		intfName: intf.Name,
	}

	if err := s.reconnect(); err != nil {
		return nil, err
	}

	return s, nil
}

// reconnect waits for the interface and reopens pcap
func (s *rawSocket) reconnect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close old handle if present
	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}

	// Wait for interface to exist and be UP
	for {
		intf, err := net.InterfaceByName(s.intfName)
		if err == nil && (intf.Flags&net.FlagUp) != 0 {
			break
		}

		time.Sleep(2 * time.Second)
	}

	handle, err := safeOpenLive(
		s.intfName,
		65536,
		true,
		pcap.BlockForever,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to open interface %s: %w",
			s.intfName,
			err,
		)
	}

	s.handle = handle
	return nil
}

// Read reads one packet from the interface
func (s *rawSocket) Read() ([]byte, error) {
	for {
		handle := s.getHandle()

		data, _, err := handle.ZeroCopyReadPacketData()
		if err == nil {
			return data, nil
		}

		// Common recoverable errors
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}

		// Interface likely disappeared/reset
		if reconnectErr := s.reconnect(); reconnectErr != nil {
			time.Sleep(2 * time.Second)
			continue
		}
	}
}

// Write sends raw bytes to the interface
func (s *rawSocket) Write(data []byte) error {
	for {
		handle := s.getHandle()

		err := handle.WritePacketData(data)
		if err == nil {
			return nil
		}

		// Try reconnecting on failure
		if reconnectErr := s.reconnect(); reconnectErr != nil {
			time.Sleep(2 * time.Second)
		}
	}
}

// Close releases resources
func (s *rawSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}

	return nil
}

func (s *rawSocket) getHandle() *pcap.Handle {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.handle
}

func safeOpenLive(
	device string,
	snaplen int32,
	promisc bool,
	timeout time.Duration,
) (_ *pcap.Handle, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pcap panic: %v", r)
		}
	}()

	return pcap.OpenLive(
		device,
		snaplen,
		promisc,
		timeout,
	)
}
