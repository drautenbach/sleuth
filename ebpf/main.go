package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		log.Fatalf("invalid IPv4: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <bpf-object> <empirical-ip> <real-ip>\n", os.Args[0])
		os.Exit(1)
	}

	objPath := os.Args[1]
	empiricalIP := ipToUint32(os.Args[2])
	realIP := ipToUint32(os.Args[3])

	// Load compiled eBPF object (clang -target bpf ...)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	defer coll.Close()

	// Get map
	natMap := coll.Maps["nat_map"]
	if natMap == nil {
		log.Fatalf("nat_map not found")
	}

	// Insert mapping
	err = natMap.Put(empiricalIP, realIP)
	if err != nil {
		log.Fatalf("updating map: %v", err)
	}

	fmt.Printf("Inserted mapping: %s -> %s\n", os.Args[2], os.Args[3])
}
