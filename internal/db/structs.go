package db

import "time"

type UserProfile struct {
	UserName    	string
	FullName    	string
	EmailAddress	string
	Password    	string
	PasswordReset	time.Time
	Enabled	     	bool
	Admin	     	bool
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
