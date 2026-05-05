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
	Since        time.Time
	Until        time.Time
	ClientIP     string
	OrigIP       string
	DestIPOffset uint16
	Hostname     string
	QType        uint16
	CacheExpiry  time.Time
	DNSExpiry    time.Time
	BytesUsed    uint64
	ReasonCode   uint16
}
