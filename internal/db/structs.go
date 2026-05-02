package db

import "time"

type UserProfile struct {
	UserName      string
	FullName      string
	EmailAddress  string
	Password      string
	PasswordReset time.Time
	Enabled       bool
	Role          string
}

type SystemProfile struct {
	Profilename     string
	NetworkAdapters map[string]struct {
		MACAddress string
		DHCP       bool
		Enabled    bool
	}
}

type DeviceProfile struct {
	MACAddress string
	DeviceName string
	HostName   string
	UserName   string
	Enabled    bool
}

type Role struct {
	RoleName   string
	SystemRole bool
	Admin      bool
}

type Settings struct {
	Mode           enumPortalMode
	DefaultRole    string
	SelfRegEnabled bool
	Firewall       string
}

type enumPortalMode int

const (
	ModeCaptive enumPortalMode = iota
	ModeAllow                  = 1
	ModeBlock                  = 0
)

type Session struct {
	IP       string
	Username string
	Expiry   time.Time
}

type DNSCategory struct {
	CategoryId   string
	CategoryName string
	Enabled      bool
}

type DNSRuleSet struct {
	RuleSetId   string
	RuleSetName string
	Description string
	CategoryId  string
	External    bool
	Source      string
	Schedule    string
	Rules       []string
	Enabled     bool
}
