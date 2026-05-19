package security

import (
	"fmt"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/network"
	"strings"
)

type Security struct {
	settings *db.Settings
	db       *db.Db
	network  *network.Network
}

func InitSession(db *db.Db, network *network.Network, settings *db.Settings) *Security {
	return &Security{db: db, network: network, settings: settings}
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

func (s *Security) CreateSession(IP string, Username string, MacAddress string) *db.Session {
	session := &db.Session{
		IP:         IP,
		Username:   Username,
		MacAddress: MacAddress,
	}
	s.db.CreateSession(session)
	return session
}

func (s *Security) VerifyDomainAccess(clientIP string, hostname string) (bool, uint16) {
	var user *db.UserProfile
	var macaddress string

	if session := s.db.GetSession(clientIP); session != nil {
		if user = s.db.GetUser(session.Username); user != nil && user.Enabled {
			return true, constants.AccessAllowed
		}
	} else {
		if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil && user.Enabled {
			s.CreateSession(clientIP, user.UserName, macaddress)
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

type SessionInfo struct {
	ClientIP     string
	Username     string
	Role         string
	DNS          *db.DNSConfiguration
	RejectReason uint16
}

func (s *Security) GetSessionInfo(clientIP string) (SessionInfo, error) {
	var user *db.UserProfile
	var macaddress string
	var ses *db.Session

	sessionInfo := SessionInfo{
		ClientIP:     clientIP,
		RejectReason: constants.AccessBlockedUnauthorised,
	}

	if ses = s.db.GetSession(clientIP); ses != nil {
		user = s.db.GetUser(ses.Username)
	} else {
		if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil && user.Enabled && user.Role != "" {
			ses = s.CreateSession(clientIP, user.UserName, macaddress)
		}
	}

	if ses == nil {
		settings := s.db.GetSettings()
		if settings.Mode != db.ModeBlock {
			sessionInfo.RejectReason = constants.AccessBlockedNotAuthenticated
		}
		return sessionInfo, nil
	}

	sessionInfo.Username = user.UserName
	role := s.db.GetRole(user.Role)
	if role == nil {
		return sessionInfo, fmt.Errorf("Could not locate role %s for user: %s", user.Role, user.UserName)
	}
	sessionInfo.Role = role.RoleName
	sessionInfo.RejectReason = constants.AccessAllowed
	if role.DNSOverride && role.DNSAddress != "" {
		sessionInfo.DNS = &db.DNSConfiguration{
			Address: role.DNSAddress,
			Type:    role.DNSMode,
		}
	} else if role.DNSConfiguration != "" {
		if dns := s.db.GetDNSConfiguration(role.DNSConfiguration); dns != nil {
			sessionInfo.DNS = dns
		}
	}
	if sessionInfo.DNS == nil {
		sessionInfo.DNS = &db.DNSConfiguration{
			Address: s.settings.FallbackDNS,
			Type:    0,
		}
	}
	if sessionInfo.DNS.Type > 0 && role.DNSPrependDeviceName && ses.MacAddress != "" {
		if d := s.db.GetDevice(ses.MacAddress); d != nil {
			if d.DeviceName != "" {
				sessionInfo.DNS.Address = strings.ReplaceAll(d.DeviceName, " ", "--") + "-" + sessionInfo.DNS.Address
			} else if d.HostName != "" {
				sessionInfo.DNS.Address = strings.ReplaceAll(d.HostName, " ", "--") + "-" + sessionInfo.DNS.Address
			}
		}

	}
	return sessionInfo, nil

}

func (s *Security) ResolveMacAddress(clientIP string) string {
	node := s.network.FindByIP(clientIP)
	if node != nil {
		return node.Mac.String()
	}
	return network.Search(clientIP)
}

func (s *Security) ResolveUserByMacAddress(clientIP string) (*db.UserProfile, string) {
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
			return nil, ""
		}
		username = settings.DefaultRole
	} else {
		device = s.db.GetDevice(macaddress)
		deviceName := ""

		if device == nil {
			if settings.Mode == db.ModeBlock {
				return nil, ""
			}
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
		} else if device.UserName != "" {
			return s.db.GetUser(device.UserName), macaddress
		} else {
			return nil, ""
		}

		if settings.Mode == db.ModeCaptive {
			return nil, ""
		}

		username = deviceName
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
			return nil, ""
		}
	}

	if device != nil {
		device.UserName = user.UserName
		if s.db.UpdateDevice(device) == nil {
			return user, macaddress
		}
	}

	return user, macaddress
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
