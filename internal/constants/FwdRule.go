package constants

import (
	"time"
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
}
