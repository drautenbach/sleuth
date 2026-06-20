package security

import (
	"fmt"
	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/log"
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
	var err error
	session := &db.Session{
		IP:            IP,
		Username:      Username,
		MacAddress:    MacAddress,
		ReasonCode:    ReasonCode,
		AccessProfile: AccessProfile,
	}
	if s.db.GetSession(IP) == nil {
		err = s.db.CreateSession(session)
	} else {
		err = s.db.DeleteSession(IP)
		if err == nil {
			err = s.db.CreateSession(session)
		}
	}
	if err != nil {
		log.Error(err)
		return nil
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

func (s *Security) VerifySessionAccess(clientIP string) (bool, uint16) {
	var user *db.UserProfile
	var macaddress string
	//var username = ""
	var accessprofile = ""
	var role = s.settings.DefaultRole
	reasoncode := constants.AccessBlockedNotAuthenticated

	if session := s.db.GetSession(clientIP); session != nil {
		if session.ReasonCode > 0 {
			return false, session.ReasonCode
		}
		if session.Username != "" {
			if user = s.db.GetUser(session.Username); user != nil {
				if user.Enabled {
					return true, constants.AccessAllowed
				} else {
					//username = user.UserName
					reasoncode = constants.AccessBlockedUnauthorised
					accessprofile = user.AccessProfile
					return false, session.ReasonCode
				}
			}

		}
	} else if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil {
		if user.Enabled {
			role = user.Role
			accessprofile = user.AccessProfile
			s.SetSession(clientIP, user.UserName, macaddress, 0, accessprofile)
			return true, constants.AccessAllowed
		} else {
			//username = user.UserName
			reasoncode = constants.AccessBlockedUnauthorised
		}
	}

	r := s.db.GetRole(role)
	if r != nil {
		aps := GetActiveAccessProfiles(r)
		if accessprofile == "" || slices.Index(aps, accessprofile) == -1 {
			if len(aps) > 0 {
				accessprofile = aps[0]
			} else {
				accessprofile = ""
			}
		}
	} else {
		accessprofile = ""
	}

	if s.settings.Mode == db.ModeBlock {
		reasoncode = constants.AccessBlockedUnauthorised
	}
	//s.SetSession(clientIP, username, macaddress, reasoncode, accessprofile)
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
	Reevaluate     bool
}

func (s *Security) GetSessionInfo(clientIP string) (SessionInfo, error) {
	var user *db.UserProfile
	var macaddress string
	var role *db.Role
	ses := s.db.GetSession(clientIP)

	sessionInfo := SessionInfo{
		ClientIP:     clientIP,
		RejectReason: constants.AccessBlockedUnauthorised,
	}

	if ses != nil {
		sessionInfo.RejectReason = ses.ReasonCode
		if /*ses.MacAddress != "" &&*/ ses.Username != "" {
			user = s.db.GetUser(ses.Username)
		} else {
			role = s.db.GetRole(s.settings.DefaultRole)
		}
		if ses.ReasonCode > 0 {
			return sessionInfo, nil
		}
	} else {
		if user, macaddress = s.ResolveUserByMacAddress(clientIP); user != nil && user.Enabled && user.Role != "" {
			ses = s.SetSession(clientIP, user.UserName, macaddress, 0, user.AccessProfile)
			sessionInfo.Reevaluate = true
		}
	}

	if ses == nil {
		switch s.settings.Mode {
		case db.ModeAllow:
			role = s.db.GetRole(s.settings.DefaultRole)
			if role != nil {
				//sessionInfo.Role = s.settings.DefaultRole
				//sessionInfo.DynamicRouting = role.DynamicRouting
				sessionInfo.RejectReason = constants.AccessAllowed
			} else {
				return sessionInfo, fmt.Errorf("Could not locate default role (%s)", s.settings.DefaultRole)
			}
		case db.ModeCaptive:
			sessionInfo.RejectReason = constants.AccessBlockedNotAuthenticated
			//return sessionInfo, nil
		case db.ModeBlock:
			sessionInfo.RejectReason = constants.AccessBlockedUnauthorised
			//return sessionInfo, nil

		}
	}

	if user != nil {
		sessionInfo.Username = user.UserName
		role = s.db.GetRole(user.Role)
		if role == nil {
			return sessionInfo, fmt.Errorf("Could not locate role %s for user: %s", user.Role, user.UserName)
		}
	}
	if role != nil {
		ap := GetActiveAccessProfiles(role)
		if ses != nil && ses.AccessProfile != "" && slices.Index(ap, ses.AccessProfile) > -1 {
			sessionInfo.AccessProfile = s.db.GetAccessProfile(ses.AccessProfile)
		} else if sessionInfo.AccessProfile == nil || slices.Index(ap, sessionInfo.AccessProfile.Name) == -1 {
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
	}

	//sessionInfo.RejectReason = constants.AccessAllowed

	if sessionInfo.DNS == nil {
		sessionInfo.DNS = &db.DNSConfiguration{
			Address: s.settings.FallbackDNS,
			Type:    0,
		}
	}
	if sessionInfo.DNS.Type > 0 {
		if role.DNSPrependDeviceName {
			if ses != nil && ses.MacAddress != "" {
				if d := s.db.GetDevice(ses.MacAddress); d != nil {
					if d.DeviceName != "" {
						sessionInfo.DNS.Address = strings.ReplaceAll(d.DeviceName, " ", "--") + "-" + sessionInfo.DNS.Address
					} else if d.HostName != "" {
						sessionInfo.DNS.Address = strings.ReplaceAll(d.HostName, " ", "--") + "-" + sessionInfo.DNS.Address
					}
				}
			}
		}

	}
	if ses == nil {
		ap := ""
		if sessionInfo.AccessProfile != nil {
			ap = sessionInfo.AccessProfile.Name
		}
		s.SetSession(sessionInfo.ClientIP, sessionInfo.Username, macaddress, sessionInfo.RejectReason, ap)
		sessionInfo.Reevaluate = true
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

func VerifyDomainAccess(ses SessionInfo, dns *constants.DNSSession) {
	if ses.RejectReason != constants.AccessBlockedNotAuthenticated && ses.RejectReason != constants.AccessBlockedUnauthorised {
		if ses.AccessProfile == nil {
			dns.ReasonCode = constants.AccessBlockedRule
		} else {
			if len(ses.AccessProfile.AllowedDomains) > 0 || len(ses.AccessProfile.BlockedDomains) > 0 {
				name := strings.ToLower(strings.TrimRight(dns.Hostname, "."))
				for i := range ses.AccessProfile.AllowedDomains {
					if name == ses.AccessProfile.AllowedDomains[i] {
						dns.ReasonCode = constants.AccessAllowed
						return
					} else if len(name) > len(ses.AccessProfile.AllowedDomains[i]) && name[len(ses.AccessProfile.AllowedDomains[i]):] == ses.AccessProfile.AllowedDomains[i] {
						dns.ReasonCode = constants.AccessAllowed
						return
					}
				}
				for i := range ses.AccessProfile.BlockedDomains {
					if name == ses.AccessProfile.BlockedDomains[i] {
						dns.ReasonCode = constants.AccessBlockedRule
						return
					} else if len(name) > len(ses.AccessProfile.BlockedDomains[i]) {
						test := name[len(name)-len(ses.AccessProfile.BlockedDomains[i])-1:]
						if test == "."+ses.AccessProfile.BlockedDomains[i] {
							dns.ReasonCode = constants.AccessBlockedRule
							return
						}
					}
				}
			}
			dns.ReasonCode = constants.AccessAllowed
		}
	}
}
