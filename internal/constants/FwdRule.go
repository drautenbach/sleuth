package constants

import (
	"time"
)

const (
	AccessAllowed                 uint16 = 0
	AccessBlockedNotAuthenticated uint16 = 1
	AccessBlockedUnauthorised     uint16 = 2
	AccessBlockedRuleSet          uint16 = 3
	AccessBlockedTimeLimit        uint16 = 3
	AccessBlockBandwidthLimit     uint16 = 4
)

type FwdRule struct {
	ClientIP    string
	InterfaceIP string
	HostName    string
	ReasonCode  uint16
	TargetIP    string
	AllocatedIP string
}

type DNSSession struct {
	Since       time.Time
	ClientIP    string
	InterfaceIP string
	//OrigIP       string
	//DestIP       string
	//DestIPOffset uint16
	Hostname      string
	QType         uint16
	LastEvent     time.Time
	SessionExpiry time.Time
	DNSExpiry     time.Time
	BytesUsed     uint64
	ReasonCode    uint16
	DNSResponse   DNSResponse
}

type DNS_IP_Record struct {
	Name        string `json:"name"`
	TTL         uint32 `json:"ttl"`
	Class       string `json:"class"`
	IP          string `json:"ip"`
	AllocatedIP string `json:"allocatedIP"`
}

type DNSResponse struct {
	A    *DNS_IP_Record `json:"A"`
	AAAA *DNS_IP_Record `json:"AAA"`
	Raw  []string       `json:"raw"`
}

type ReverseDNS struct {
	IP           string
	DestIP       string
	DestIPOffset uint16
	Hostname     string
}
