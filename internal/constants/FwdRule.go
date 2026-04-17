package constants

import "time"

type FwdRule struct {
	ClientIP string
	OrigIP   string
	TempIP   string
	Hostname string
	Expires  time.Time
}
