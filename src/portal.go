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
	"sleuth/internal/firewall"
	"sleuth/internal/network"

	"github.com/gin-gonic/gin"
)

type Portal struct {
	db      *db.Db
	network *network.Network
	fw      firewall.FirewallManager
	server  WebServer
	config  GlobalConfiguration
}

func InitPortal() *Portal {
	p := &Portal{
		db:      db.InitDB("/tmp/sleuth/data/"),
		network: network.InitNetwork(),
		fw:      firewall.InitFirewall(),
	}
	p.server = *initWebServer(60*time.Minute, p.interceptHandler)
	p.config = GlobalConfiguration{
		settings: p.db.GetSettings(),
	}

	wcSystemInit(p)
	wcSetupInit(p)
	wcProfilesInit(p)
	webShellInit(p)

	return p
}

func (p *Portal) interceptHandler(c *gin.Context) {
	//ip := clientIP(c.Request)
	if p.isAllowed(c) {
		c.Next()
		return
	}

	var err error
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
					token, exp, serr := p.server.CreateSessionToken(u.UserName)
					if serr == nil {
						maxAge := int(time.Until(exp).Seconds())
						c.SetCookie("sleuth_session", token, maxAge, "/", "", false, true)
						c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
						return
					}
					err = serr
				} else {
					err = fmt.Errorf("invalid username or password")
				}
			} else {
				err = fmt.Errorf("invalid username or password")
			}
		}

	}

	p.server.HTML(c, "admin_login", gin.H{
		"next":  c.Query("next"),
		"error": err,
	})
	c.Abort()
}

func (p *Portal) isAllowed(c *gin.Context) bool {

	// 1) Check JWT cookie or Authorization: Bearer token
	var tokenStr string
	if cookie, err := c.Cookie("sleuth_session"); err == nil {
		tokenStr = cookie
	} else {
		if auth := c.Request.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tokenStr = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if tokenStr != "" {
		if _, err := p.server.ValidateSessionToken(tokenStr); err == nil {
			return true
		}
	}

	// 2) Check by MAC address if client is allowed
	ip := clientIP(c.Request)
	macaddress := network.Search(ip)
	node := p.network.Find(ip)
	if node != nil {
		macaddress = node.Mac.String()
	}
	if macaddress != "" {
		device := p.db.GetDevice(macaddress)
		if device == nil {
			deviceName := "Unknown"
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
			p.db.CreateDevice(&db.DeviceProfile{
				MACAddress: macaddress,
				DeviceName: deviceName,
				HostName:   deviceName,
			})
		}
	}

	// 3) Static content on the web server should always be allowed
	if p.server.isWebHost(strings.Split(c.Request.Host, ":")[0]) {
		if c.Request.Method == http.MethodGet {
			info, err := os.Stat("./www" + c.Request.URL.Path)
			if info != nil && (os.IsExist(err) || !info.IsDir()) {
				return true
			}
		}
	}

	return false
}
