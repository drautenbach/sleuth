package main

// A simple in-memory captive portal. It uses the client's IP address
// to gate access: unknown IPs are redirected to /captive where they
// can accept terms and be added to an allowlist for a short TTL.

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"sleuth/internal/db"
	"sleuth/internal/dns"
	"sleuth/internal/firewall"
	"sleuth/internal/network"
	"sleuth/internal/rules"
	"sleuth/internal/security"

	"github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
)

type WebControllers struct {
	System    wcSystem
	Setup     wcSetup
	Stats     wcStats
	Profiles  wcProfiles
	DNSConfig wcDnsConfig
}

type Portal struct {
	db       *db.Db
	security *security.Security
	network  *network.Network
	server   WebServer
	config   GlobalConfiguration
	fw       firewall.FirewallManager
	wc       WebControllers
	dns      dns.DnsServer
	rules    rules.DNSRulesEngine
}

func InitPortal() *Portal {
	p := &Portal{
		db:      db.InitDB("/tmp/sleuth/data/"),
		network: network.InitNetwork(),
		fw:      firewall.LoadFirewallManager(),
		wc:      WebControllers{},
	}
	p.security = security.InitSession(p.db)
	p.fw.Init(p.db)
	p.config = GlobalConfiguration{
		settings: p.db.GetSettings(),
	}
	p.rules = *rules.Init(p.db)
	p.rules.InitDefaults()
	p.fw.SetActiveFirewall(p.config.settings.Firewall)
	p.dns = *dns.InitDnsServer(p.fw, p.security)
	p.server = *initWebServer(60*time.Minute, p.interceptHandler)

	p.wc.System = *wcSystemInit(p)
	p.wc.Setup = *wcSetupInit(p)
	p.wc.Profiles = *wcProfilesInit(p)
	p.wc.Stats = *wcStatsInit(p)
	p.wc.DNSConfig = *wcDnsConfigInit(p)
	p.server.router.GET("/logout", p.logout)

	webShellInit(p)

	return p
}

func (p *Portal) logout(c *gin.Context) {
	is_portal, page := p.isPortalRequest(c)
	if is_portal && page != "portal_session" {
		c.SetCookie("sleuth_session", "", -1, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/")
	} else {
		p.security.ClearSession(clientIP(c.Request))
		allrules := p.db.GetFwdRulesByClient(clientIP(c.Request))
		for i := range allrules {
			if allrules[i].ReasonCode == 0 {
				p.dns.ReevaluateDomainAccess(&allrules[i])
			}
		}
		c.Header("connection", "close")
		if page == "portal_session" {
			c.Redirect(http.StatusMovedPermanently, "/")
		}
		c.Redirect(http.StatusSeeOther, c.Request.URL.String())
	}
}
func (p *Portal) isPortalRequest(c *gin.Context) (bool, string) {
	is_portal := true
	page := "portal_login"
	host := ""
	ip := clientIP(c.Request)
	session, _ := p.security.GetSession(ip)
	loc := location.Get(c)
	if loc != nil {
		host = loc.Host
		if loc.Host != ip {
			fwr := p.db.GetFwdRuleByHostname(ip, loc.Host+".", 1)
			if fwr != nil {
				is_portal = false
				if host == "cp.local" {
					if fwr.ReasonCode == 0 {
						page = "portal_session"
					} else {
						page = "session_login"
					}
				} else {
					if fwr.ReasonCode == 0 {
						page = "portal_valid"
					} else if fwr.ReasonCode == 1 && session != "" {
						p.dns.ReevaluateDomainAccess(fwr)
					}
					c.Header("connection", "close")
				}
			}
		}
	}
	return is_portal, page
}

type requestType struct {
	isAdminPortal   bool
	sessionUser     string
	serveTemplate   string
	host            string
	resourceRequest bool
}

func (p *Portal) determineRequest(c *gin.Context) requestType {
	var rt = &requestType{
		isAdminPortal: true,
	}
	ip := clientIP(c.Request)
	loc := location.Get(c)
	host := ""
	if loc != nil {
		host = loc.Host
		if loc.Host != ip {
			fwr := p.db.GetFwdRuleByHostname(ip, loc.Host+".", 1)
			if fwr != nil {
				rt.isAdminPortal = false
				rt.sessionUser, _ = p.security.GetSession(ip)
				rt.serveTemplate = "session_login"

				if host == "cp.local" {
					if fwr.ReasonCode == 0 {
						rt.serveTemplate = "portal_session"
					}
				} else {
					if fwr.ReasonCode == 0 {
						rt.serveTemplate = "portal_valid"
					} else if fwr.ReasonCode == 1 && rt.sessionUser != "" {
						p.dns.ReevaluateDomainAccess(fwr)
					}
					c.Header("connection", "close")
				}
			}
		}
	}

	if rt.isAdminPortal {
		var tokenStr string
		if cookie, err := c.Cookie("sleuth_session"); err == nil {
			tokenStr = cookie
		} else {
			if auth := c.Request.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				tokenStr = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if tokenStr != "" {
			if token, err := p.server.ValidateSessionToken(tokenStr); err == nil {
				rt.sessionUser = token
			}
		} else {
			rt.serveTemplate = "portal_login"
		}
	}

	if c.Request.Method == http.MethodGet {
		info, err := os.Stat("./www" + c.Request.URL.Path)
		if info != nil && (os.IsExist(err) || !info.IsDir()) {
			rt.resourceRequest = true
		}
	}

	return *rt
}

func (p *Portal) interceptHandler(c *gin.Context) {
	var err error
	message := ""
	rt := p.determineRequest(c)

	if c.Request.Method == http.MethodPost && c.Request.FormValue("sleuth_action") != "" {
		var action = c.Request.FormValue("sleuth_action")
		switch action {
		case "reset_password":
			u := p.db.GetUser(c.Request.FormValue("username"))
			if u != nil {
				if u.PasswordReset.After(time.Now()) {
					newPassword := c.Request.FormValue("new_password")
					confirmPassword := c.Request.FormValue("confirm_password")
					if newPassword == confirmPassword {
						p.db.SetPassword(u.UserName, newPassword)
						c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
						/*token, exp, serr := p.server.CreateSessionToken(u.UserName)
						if serr == nil {
							maxAge := int(time.Until(exp).Seconds())
							c.SetCookie("sleuth_session", token, maxAge, "/", "", false, true)
							c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
							return
						}
						err = serr*/
					} else {
						err = fmt.Errorf("passwords do not match")
					}
				} else {
					err = fmt.Errorf("password reset has expired")
				}
			} else {
				err = fmt.Errorf("user %s does not exist", c.Request.FormValue("username"))
			}
		case "logout":
			p.logout(c)
			return
		case "login":
			u := p.db.GetUser(c.Request.FormValue("username"))
			if u != nil {
				if u.PasswordReset.After(time.Now()) {
					p.server.HTML(c, "reset_password", gin.H{
						"username": c.Request.FormValue("username"),
						"next":     c.Query("next"),
						"error":    err,
					})
					c.Abort()
					return
				} else if u.Password == c.Request.FormValue("password") {
					if rt.isAdminPortal {
						if p.security.IsAllowedPortalAccess(u.UserName) {
							token, exp, serr := p.server.CreateSessionToken(u.UserName)
							if serr == nil {
								maxAge := int(time.Until(exp).Seconds())
								c.SetCookie("sleuth_session", token, maxAge, "/", "", false, true)
								c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
								return
							} else {
								err = serr
							}
						} else {
							err = fmt.Errorf("access denied")
						}
					} else {
						p.security.CreateSession(clientIP(c.Request), u.UserName)
						allrules := p.db.GetFwdRulesByClient(clientIP(c.Request))
						for i := range allrules {
							if allrules[i].ReasonCode != 0 {
								p.dns.ReevaluateDomainAccess(&allrules[i])
							}
						}
						c.Header("connection", "close")
						c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
						return
					}

				} else {
					err = fmt.Errorf("access denied")
				}
			} else {
				err = fmt.Errorf("access denied")
			}
		}

	} else if (rt.isAdminPortal && rt.sessionUser != "") || rt.resourceRequest {
		c.Next()
		return
	}

	portal_address := ""
	if !rt.isAdminPortal || rt.serveTemplate == "session_login" {
		if_ip, _ := network.GetInterfaceIP(clientIP(c.Request))
		if if_ip != "" {
			portal_address = "http://" + if_ip
		} else {
			portal_address = "http://127.0.0.1"
		}
	}
	p.server.HTML(c, rt.serveTemplate, gin.H{
		"next":           c.Query("next"),
		"ip":             clientIP(c.Request),
		"portal_address": portal_address,
		"error":          err,
		"message":        message,
	})
	if rt.serveTemplate != "portal_session" || c.Request.URL.Path != "/logout" {
		c.Abort()
	}
}

func (p *Portal) isAllowed(c *gin.Context) bool {

	// 1) Static content on the web server should always be allowed
	//if p.server.isWebHost(strings.Split(c.Request.Host, ":")[0]) {

	//}

	ip := clientIP(c.Request)
	/*if username, err := p.security.GetSession(ip); err == nil {
		return p.security.IsAllowedPortalAccess(username)
	}*/

	// 2) Check JWT cookie or Authorization: Bearer token

	// 3) Check by MAC address if client is allowed
	macaddress := network.Search(ip)
	node := p.network.FindByIP(ip)
	if node != nil {
		macaddress = node.Mac.String()
	}
	if macaddress != "" {
		device := p.db.GetDevice(macaddress)
		if device == nil {
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
			p.db.CreateDevice(&db.DeviceProfile{
				MACAddress: macaddress,
				DeviceName: name,
				HostName:   deviceName,
			})
		} else if device.UserName != "" {
			return p.security.IsAllowedPortalAccess(device.UserName)
		}

	}

	return false
}
