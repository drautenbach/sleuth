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
	DNSName    string
	UserName   string
	Enabled    bool
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
	IP         string
	Username   string
	MacAddress string
	Expiry     time.Time
	ReasonCode uint16
}

type HttpProxy struct {
	DomainName string
	URL        string
	SSL        bool
	Enabled    bool
}
