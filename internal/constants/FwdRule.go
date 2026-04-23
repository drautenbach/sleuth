package constants

import "time"

type FwdRule struct {
	ClientIP     string
	OrigIP       string
	DestIPOffset uint16
	Hostname     string
	QType        uint16
	CacheExpiry  time.Time
	DNSExpiry    time.Time
}
