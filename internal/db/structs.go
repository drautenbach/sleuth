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
}

type enumPortalMode int

const (
	ModeCaptive enumPortalMode = iota
	ModeAllow                  = 1
	ModeBlock                  = 0
)
