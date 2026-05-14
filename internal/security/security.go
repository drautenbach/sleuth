package security

import (
	"fmt"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/network"
)

type Security struct {
	db      *db.Db
	network *network.Network
}

func InitSession(db *db.Db, network *network.Network) *Security {
	return &Security{db: db, network: network}
}

func (s *Security) GetSession(IP string) (string, error) {
	ses := s.db.GetSession(IP)
	if ses != nil {
		return ses.Username, nil
	}
	return "", fmt.Errorf("session does not exist")
}

func (s *Security) ClearSession(IP string) error {
	return s.db.DeleteSession(IP)
}

func (s *Security) CreateSession(IP string, Username string) {
	s.db.CreateSession(&db.Session{
		IP:       IP,
		Username: Username,
	})
}

func (s *Security) VerifyDomainAccess(clientIP string, hostname string) (bool, uint16) {
	var user *db.UserProfile

	if session := s.db.GetSession(clientIP); session != nil {
		if user = s.db.GetUser(session.Username); user != nil && user.Enabled {
			return true, constants.AccessAllowed
		}
	} else {
		if user = s.ResolveUserByMacAddress(clientIP); user != nil && user.Enabled {
			s.CreateSession(clientIP, user.UserName)
			return true, constants.AccessAllowed
		}
	}

	settings := s.db.GetSettings()
	if settings.Mode == db.ModeBlock {
		return false, constants.AccessBlockedUnauthorised
	} else {
		return false, constants.AccessBlockedNotAuthenticated
	}

}

func (s *Security) ResolveUserByMacAddress(clientIP string) *db.UserProfile {
	settings := s.db.GetSettings()

	macaddress := network.Search(clientIP)
	node := s.network.FindByIP(clientIP)
	if node != nil {
		macaddress = node.Mac.String()
	}

	var device *db.DeviceProfile
	var username string
	if macaddress == "" {
		if settings.Mode != db.ModeAllow {
			return nil
		}
		username = settings.DefaultRole
	} else {
		device = s.db.GetDevice(macaddress)
		if device == nil {
			if settings.Mode == db.ModeBlock {
				return nil
			}
			deviceName := ""
			if node != nil {
				if node.Mdns != "" {
					deviceName = node.Mdns
				}
				if node.Nbns != "" {
					deviceName = node.Nbns
				}
				if node.Dns != "" {
					deviceName = node.Dns
				}
			}
			name := deviceName
			if name == "" {
				name = "Unknown"
			}
			s.db.CreateDevice(&db.DeviceProfile{
				MACAddress: macaddress,
				DeviceName: name,
				HostName:   deviceName,
			})
		}

		if device.UserName != "" {
			return s.db.GetUser(device.UserName)
		}

		if settings.Mode == db.ModeCaptive {
			return nil
		}

		username := device.DeviceName
		if username == "" || username == "Unknown" {
			username = settings.DefaultRole
		}

	}

	user := s.db.GetUser(username)
	if user == nil {
		user = &db.UserProfile{
			UserName: username,
			FullName: username,
			Enabled:  true,
			Role:     settings.DefaultRole,
		}
		if s.db.CreateUser(user) != nil {
			return nil
		}
	}

	if device != nil {
		device.UserName = user.UserName
		if s.db.UpdateDevice(device) == nil {
			return user
		}
	}

	return user
}

func (s *Security) IsAllowedPortalAccess(Username string) bool {
	user := s.db.GetUser(Username)
	if user != nil {
		if user.Enabled {
			role := s.db.GetRole(user.Role)
			if role != nil {
				return role.Admin
			}
		}
	}
	return false
}
