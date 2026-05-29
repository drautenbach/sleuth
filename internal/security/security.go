package security

import (
	"fmt"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/network"
	"slices"
	"strings"
	"time"
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

func (s *Security) ForceLogout(IP string) error {
	ses := s.db.GetSession(IP)
	if ses != nil {
		s.db.DeleteSession(IP)
		ses.Username = ""
	} else {
		ses = &db.Session{
			IP: IP,
		}
	}
	ses.ReasonCode = constants.AccessBlockedNotAuthenticated
	return s.db.CreateSession(ses)
}

func (s *Security) ClearSession(IP string) error {
	return s.db.DeleteSession(IP)
}

func (s *Security) SetSession(IP string, Username string, MacAddress string, ReasonCode uint16, AccessProfile string) *db.Session {
	session := s.db.GetSession(IP)
	if session == nil {
		session := &db.Session{
			IP:            IP,
			Username:      Username,
			MacAddress:    MacAddress,
			ReasonCode:    ReasonCode,
			AccessProfile: AccessProfile,
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

func (s *Security) SetAccessProfile(clientIP string, accessprofile string) error {
	ses := s.db.GetSession(clientIP)
	role := ""
	var user *db.UserProfile
	if ses == nil {
		return fmt.Errorf("Could not find session to set access profile for client IP %s", clientIP)
	}
	if ses.Username != "" {
		user = s.db.GetUser(ses.Username)
		role = user.Role
	} else {
		role = s.settings.DefaultRole
	}
	if role == "" {
		return fmt.Errorf("Could not identify role to set access profile for client IP %s", clientIP)
	}
	profiles := GetActiveAccessProfiles(s.db.GetRole(role))
	if slices.Index(profiles, accessprofile) > -1 {
		ses.AccessProfile = accessprofile
		s.db.DeleteSession(clientIP)
		s.db.CreateSession(ses)
		if user != nil {
			user.AccessProfile = accessprofile
			s.db.UpdateUser(user)
		}

	} else {
		return fmt.Errorf("Access profile %s not available", accessprofile)
	}
	return nil
}

func (s *Security) VerifyDomainAccess(clientIP string, hostname string) (bool, uint16) {
	var user *db.UserProfile
	var macaddress string
	var username = ""
	var accessprofile = ""
	reasoncode := constants.AccessBlockedNotAuthenticated

	if session := s.db.GetSession(clientIP); session != nil {
		if user = s.db.GetUser(session.Username); user != nil {
			if user.Enabled {
				return true, constants.AccessAllowed
			} else {
				username = user.UserName
				reasoncode = constants.AccessBlockedUnauthorised
				accessprofile = user.AccessProfile
			}
		}
		return false, session.ReasonCode
	} else {
		if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil {
			if user.Enabled {
				accessprofile = user.AccessProfile
				s.SetSession(clientIP, user.UserName, macaddress, 0, accessprofile)
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
	s.SetSession(clientIP, username, macaddress, constants.AccessBlockedUnauthorised, accessprofile)
	return false, reasoncode

}

type SessionInfo struct {
	ClientIP       string
	Username       string
	Role           string
	DynamicRouting bool
	AccessProfile  *db.AccessProfile
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
			ses = s.SetSession(clientIP, user.UserName, macaddress, 0, user.AccessProfile)
		}
	}

	var role *db.Role
	if ses == nil || user == nil {
		switch s.settings.Mode {
		case db.ModeAllow:
			role = s.db.GetRole(s.settings.DefaultRole)
			if role != nil {
				sessionInfo.Role = s.settings.DefaultRole
				sessionInfo.DynamicRouting = role.DynamicRouting
				sessionInfo.RejectReason = constants.AccessAllowed
			} else {
				return sessionInfo, fmt.Errorf("Could not locate default role (%s)", s.settings.DefaultRole)
			}
		case db.ModeCaptive:
			sessionInfo.RejectReason = constants.AccessBlockedNotAuthenticated
			return sessionInfo, nil
		case db.ModeBlock:
			sessionInfo.RejectReason = constants.AccessBlockedUnauthorised
			return sessionInfo, nil

		}
	}

	if user != nil {
		sessionInfo.Username = user.UserName
		role = s.db.GetRole(user.Role)
		if role == nil {
			return sessionInfo, fmt.Errorf("Could not locate role %s for user: %s", user.Role, user.UserName)
		}
	}
	ap := GetActiveAccessProfiles(role)
	if sessionInfo.AccessProfile == nil || slices.Index(ap, sessionInfo.AccessProfile.Name) == -1 {
		if user != nil && user.AccessProfile != "" && slices.Index(ap, user.AccessProfile) > -1 {
			sessionInfo.AccessProfile = s.db.GetAccessProfile(user.AccessProfile)
		} else if len(ap) > 0 {
			sessionInfo.AccessProfile = s.db.GetAccessProfile(ap[0])
		} else {
			sessionInfo.AccessProfile = nil
		}
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

func IsScheduleActive(schedule db.RoleAccessSchedule, now time.Time) bool {
	weekday := int(now.Weekday())

	nowMinutes := uint16(now.Hour()*60 + now.Minute())
	fromMinutes := schedule.From.Hour*60 + schedule.From.Minute
	toMinutes := schedule.To.Hour*60 + schedule.To.Minute

	// Normal window (same-day)
	if fromMinutes <= toMinutes {
		if !schedule.Days[weekday] {
			return false
		}
		return nowMinutes >= fromMinutes && nowMinutes <= toMinutes
	}

	// Overnight window (crosses midnight)

	// Case 1: same day after "from"
	if nowMinutes >= fromMinutes {
		return schedule.Days[weekday]
	}

	// Case 2: after midnight before "to"
	prevDay := (weekday + 6) % 7
	if nowMinutes <= toMinutes {
		return schedule.Days[prevDay]
	}

	return false
}

func GetActiveAccessProfiles(r *db.Role) []string {
	ap := make([]string, 0)
	now := time.Now()
	for _, s := range r.Access.Schedule {
		if IsScheduleActive(s, now) && slices.Index(ap, s.AccessProfile) == -1 {
			ap = append(ap, s.AccessProfile)
		}
	}
	return ap
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
