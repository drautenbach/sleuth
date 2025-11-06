package db

import "time"

type UserProfile struct {
	UserName    string
	FullName    string
	Email       string
	Password    string
	Enabled     bool
	DateDeleted *time.Time
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
	HostName   string
	UserName   string
}
