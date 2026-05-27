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
		s.db.DeleteSession(IP)
		s.db.CreateSession(ses) // update ttl
		return ses.Username, nil
	}
	return "", fmt.Errorf("session does not exist")
}

func (s *Security) ClearSession(IP string) error {
	return s.db.DeleteSession(IP)
}

func (s *Security) SetSession(IP string, Username string, MacAddress string, ReasonCode uint16) *db.Session {
	session := s.db.GetSession(IP)
	if session == nil {
		session := &db.Session{
			IP:         IP,
			Username:   Username,
			MacAddress: MacAddress,
			ReasonCode: ReasonCode,
		}
		s.db.CreateSession(session)
	} else {
		s.db.DeleteSession(IP)
		if Username != "" {
			session.Username = Username
		}
		if MacAddress != "" {
			session.MacAddress = MacAddress
		}
		session.ReasonCode = ReasonCode
		s.db.CreateSession(session)
	}
	return session
}

func (s *Security) VerifyDomainAccess(clientIP string, hostname string) (bool, uint16) {
	var user *db.UserProfile
	var macaddress string
	var username = ""
	reasoncode := constants.AccessBlockedNotAuthenticated

	if session := s.db.GetSession(clientIP); session != nil {
		if user = s.db.GetUser(session.Username); user != nil {
			if user.Enabled {
				return true, constants.AccessAllowed
			} else {
				username = user.UserName
				reasoncode = constants.AccessBlockedUnauthorised
			}
		}
	} else {
		if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil {
			if user.Enabled {
				s.SetSession(clientIP, user.UserName, macaddress, 0)
				return true, constants.AccessAllowed
			} else {
				username = user.UserName
				reasoncode = constants.AccessBlockedUnauthorised
			}
		}
	}

	if s.settings.Mode == db.ModeBlock {
		reasoncode = constants.AccessBlockedUnauthorised
	}
	s.SetSession(clientIP, username, macaddress, constants.AccessBlockedUnauthorised)
	return false, reasoncode

}

type SessionInfo struct {
	ClientIP       string
	Username       string
	Role           string
	DynamicRouting bool
	DNS            *db.DNSConfiguration
	RejectReason   uint16
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
		if ses.Username != "" {
			user = s.db.GetUser(ses.Username)
		} else {
			sessionInfo.RejectReason = constants.AccessBlockedNotAuthenticated
		}
	} else {
		if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil && user.Enabled && user.Role != "" {
			ses = s.SetSession(clientIP, user.UserName, macaddress, 0)
		}
	}

	if ses == nil || user == nil {
		switch s.settings.Mode {
		case db.ModeAllow:
			r := s.db.GetRole(s.settings.DefaultRole)
			if r != nil {
				sessionInfo.Role = s.settings.DefaultRole
				sessionInfo.DynamicRouting = r.DynamicRouting
				sessionInfo.RejectReason = constants.AccessAllowed
			}
		case db.ModeCaptive:
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
	sessionInfo.DynamicRouting = role.DynamicRouting
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
	macaddress := network.Search(clientIP)
	node := s.network.FindByIP(clientIP)
	if node != nil {
		macaddress = node.Mac.String()
	}

	var device *db.DeviceProfile
	if macaddress == "" {
		return nil, ""
	} else {
		device = s.db.GetDevice(macaddress)
		deviceName := ""

		if device == nil {
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
			if name != "" {
				s.db.CreateDevice(&db.DeviceProfile{
					MACAddress: macaddress,
					DeviceName: name,
					HostName:   deviceName,
					DNSName:    deviceName,
					Enabled:    s.settings.Mode != db.ModeBlock,
				})
			}
		} else if device.UserName != "" {
			return s.db.GetUser(device.UserName), macaddress
		}
	}
	return nil, macaddress
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
