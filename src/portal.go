package main

// A simple in-memory captive portal. It uses the client's IP address
// to gate access: unknown IPs are redirected to /captive where they
// can accept terms and be added to an allowlist for a short TTL.

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"sleuth/internal/db"
	"sleuth/internal/dns"
	"sleuth/internal/firewall"
	"sleuth/internal/network"
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
	p.server = *initWebServer(60*time.Minute, p.interceptHandler)

	p.config = GlobalConfiguration{
		settings: p.db.GetSettings(),
	}
	p.fw.SetActiveFirewall(p.config.settings.Firewall)

	p.wc.System = *wcSystemInit(p)
	p.wc.Setup = *wcSetupInit(p)
	p.wc.Profiles = *wcProfilesInit(p)
	p.wc.Stats = *wcStatsInit(p)
	p.wc.DNSConfig = *wcDnsConfigInit(p)

	p.server.router.GET("/logout", func(c *gin.Context) {
		p.security.ClearSession(clientIP(c.Request))
		c.SetCookie("sleuth_session", "", -1, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/")
	})

	webShellInit(p)

	return p
}

func (p *Portal) interceptHandler(c *gin.Context) {
	var err error

	is_portal := true
	ip := clientIP(c.Request)
	if_ip, _ := dns.GetInterfaceIP(ip)
	session, _ := p.security.GetSession(ip)
	if loc := location.Get(c); loc != nil && loc.Host != "cp.local" {
		host_parts := strings.Split(loc.Host, ".")
		if len(host_parts) > 1 {
			if host_parts[len(host_parts)-2] == "cp" && session != "" {
				c.Redirect(302, "http://"+strings.Join(host_parts[:len(host_parts)-2], ".")+c.Request.URL.Path+"?"+c.Request.URL.RawQuery)
				return
			}
			if host_parts[len(host_parts)-2] != "cp" && session == "" && net.ParseIP(loc.Host) == nil {
				c.Redirect(302, "http://"+loc.Host+".cp.local"+c.Request.URL.Path+"?"+c.Request.URL.RawQuery)
				return
			}
			is_portal = host_parts[len(host_parts)-2] != "cp"
		}
	}

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
						token, exp, serr := p.server.CreateSessionToken(u.UserName)
						if serr == nil {
							maxAge := int(time.Until(exp).Seconds())
							c.SetCookie("sleuth_session", token, maxAge, "/", "", false, true)
							c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
							return
						}
						err = serr
					} else {
						err = fmt.Errorf("passwords do not match")
					}
				} else {
					err = fmt.Errorf("password reset link has expired")
				}
			} else {
				err = fmt.Errorf("user %s does not exist", c.Request.FormValue("username"))
			}
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
					p.security.CreateSession(clientIP(c.Request), u.UserName)
					token, exp, serr := p.server.CreateSessionToken(u.UserName)
					if serr == nil {
						if p.security.IsAllowedPortalAccess(u.UserName) {
							maxAge := int(time.Until(exp).Seconds())
							c.SetCookie("sleuth_session", token, maxAge, "/", "", false, true)
							c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
							return
						} else {
							err = fmt.Errorf("access denied")
						}
					} else {
						err = serr
					}
				} else {
					err = fmt.Errorf("access denied")
				}
			} else {
				err = fmt.Errorf("access denied")
			}
		}

	} else if p.isAllowed(c) {
		c.Next()
		return
	}

	portal_address := ""
	if !is_portal {
		if if_ip != "" {
			portal_address = "http://" + if_ip
		} else {
			portal_address = "http://127.0.0.1"
		}
	}
	p.server.HTML(c, "portal_login", gin.H{
		"next":           c.Query("next"),
		"ip":             ip,
		"portal_address": portal_address,
		"error":          err,
	})
	c.Abort()
}

func (p *Portal) isAllowed(c *gin.Context) bool {

	// 1) Static content on the web server should always be allowed
	//if p.server.isWebHost(strings.Split(c.Request.Host, ":")[0]) {
	if c.Request.Method == http.MethodGet {
		info, err := os.Stat("./www" + c.Request.URL.Path)
		if info != nil && (os.IsExist(err) || !info.IsDir()) {
			return true
		}
	}
	//}

	ip := clientIP(c.Request)
	if username, err := p.security.GetSession(ip); err == nil {
		return p.security.IsAllowedPortalAccess(username)
	}

	// 2) Check JWT cookie or Authorization: Bearer token
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
			p.security.CreateSession(ip, token)
			return p.security.IsAllowedPortalAccess(token)
		}
	}

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
