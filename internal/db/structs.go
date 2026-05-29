package db

import (
	"time"
)

type UserProfile struct {
	UserName      string
	FullName      string
	EmailAddress  string
	Password      string
	PasswordReset time.Time
	Enabled       bool
	Role          string
	AccessProfile string
}

type DeviceProfile struct {
	MACAddress string
	DeviceName string
	HostName   string
	DNSName    string
	UserName   string
	Enabled    bool
}

type AccessProfile struct {
	Name           string
	AllowedDomains []string
	BlockedDomains []string
}

type RoleAccessTime struct {
	Hour   uint16
	Minute uint16
}
type RoleAccessSchedule struct {
	Days          [7]bool
	From          RoleAccessTime
	To            RoleAccessTime
	AccessProfile string
}

type RoleAccess struct {
	DefaultAccessProfile string
	Schedule             []RoleAccessSchedule
}

type Role struct {
	RoleName             string
	SystemRole           bool
	Admin                bool
	DynamicRouting       bool
	DNSOverride          bool
	DNSConfiguration     string
	DNSMode              enumDNSMode
	DNSAddress           string
	DNSPrependDeviceName bool
	Access               RoleAccess
}

type Settings struct {
	Mode           enumPortalMode
	DefaultRole    string
	FallbackDNS    string
	LocalDomain    string
	SelfRegEnabled bool
	Firewall       string
	//	SSL            []string
	APIs struct {
		DomScan API_DomScan
	}
}

type API_DomScan struct {
	Key      string
	Enabled  bool
	Services struct {
		WebSiteCategorization bool
	}
}

type DNSConfiguration struct {
	ProfileId string
	Name      string
	Type      enumDNSMode
	Address   string
}

type enumPortalMode int

const (
	ModeCaptive enumPortalMode = iota
	ModeAllow                  = 1
	ModeBlock                  = 2
)

type enumDNSMode uint

const (
	ModeUDP enumDNSMode = iota
	ModeTCP             = 1
	ModeTLS             = 2
)

type Session struct {
	IP            string
	Username      string
	MacAddress    string
	Expiry        time.Time
	ReasonCode    uint16
	AccessProfile string
}

type HttpProxy struct {
	DomainName string
	SSL        bool
	URL        string
	Enabled    bool
	WAFConfig  string
}

type WafRule struct {
	ID      int
	Message string
	Tags    []string
	Phase   string
	Action  string
	File    string
	Raw     string

	IsSystem bool
}

type WAFConfiguration struct {
	Name    string
	Raw     string
	Enabled bool
}

/*


stats->daily:(role/user)->(device/mac)->date->[site:{duration, bytes}]
stats->:(role/user)->(device/mac)->date->[site:{duration, bytes}]

*/
