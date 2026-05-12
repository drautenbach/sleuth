package main

// A simple in-memory captive portal. It uses the client's IP address
// to gate access: unknown IPs are redirected to /captive where they
// can accept terms and be added to an allowlist for a short TTL.

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"sleuth/internal/constants"
	"sleuth/internal/db"
	"sleuth/internal/dns"
	"sleuth/internal/firewall"
	"sleuth/internal/network"
	"sleuth/internal/rules"
	"sleuth/internal/security"

	"github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme/autocert"
)

type WebControllers struct {
	System    wcSystem
	Setup     wcSetup
	Stats     wcStats
	Profiles  wcProfiles
	DNSConfig wcDnsConfig
}

type Portal struct {
	db          *db.Db
	security    *security.Security
	network     *network.Network
	server      WebServer
	config      GlobalConfiguration
	fw          firewall.FirewallManager
	wc          WebControllers
	dns         dns.DnsServer
	rules       rules.DNSRulesEngine
	certManager *autocert.Manager
}

func InitPortal() *Portal {
	p := &Portal{
		db:      db.InitDB("/tmp/sleuth/data/"),
		network: network.InitNetwork(),
		fw:      firewall.LoadFirewallManager(),
		wc:      WebControllers{},
	}
	p.security = security.InitSession(p.db, p.network)
	p.fw.Init(p.db)
	p.config = GlobalConfiguration{
		settings: p.db.GetSettings(),
	}
	p.rules = *rules.Init(p.db)
	p.rules.InitDefaults()
	p.fw.SetActiveFirewall(p.config.settings.Firewall)
	p.dns = *dns.InitDnsServer(p.fw, p.db, p.security)
	p.server = *initWebServer(60*time.Minute, p.interceptHandler)

	p.wc.System = *wcSystemInit(p)
	p.wc.Setup = *wcSetupInit(p)
	p.wc.Profiles = *wcProfilesInit(p)
	p.wc.Stats = *wcStatsInit(p)
	p.wc.DNSConfig = *wcDnsConfigInit(p)
	p.server.router.GET("/logout", p.logout)

	p.certManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(p.config.settings.SSL...),
		Cache:      autocert.DirCache("certs"), // folder to store certs
	}

	webShellInit(p)

	return p
}

func (p *Portal) redirectHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// decide whether redirect is needed

		wl := slices.Index(p.config.settings.SSL, r.Host) > -1

		if r.URL.Scheme == "https" && !wl {
			http.Redirect(w, r, "http://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}

		if r.URL.Scheme == "http" && wl {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Portal) redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	if slices.Index(p.config.settings.SSL, r.Host) == -1 {
		target := "http://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
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
				if host == "my.session" {
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
	blocked         bool
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
				if fwr.ReasonCode == constants.AccessBlockedUnauthorised {
					rt.serveTemplate = "session_unauthorised"
					rt.blocked = true
				} else {
					rt.serveTemplate = "session_login"
				}

				if host == "my.session" {
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

	if !rt.blocked && c.Request.Method == http.MethodPost && c.Request.FormValue("sleuth_action") != "" {
		var action = c.Request.FormValue("sleuth_action")
		switch action {
		case "reset_password":
			u := p.db.GetUser(c.Request.FormValue("username"))
			if u != nil {
				if u.PasswordReset.After(time.Now()) {
					newPassword := c.Request.FormValue("new_password")
					confirmPassword := c.Request.FormValue("confirm_password")
					if newPassword == confirmPassword {
						if err = p.db.SetPassword(u.UserName, newPassword); err == nil {
							c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
						}
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
		case "register":
			username := c.Request.FormValue("username")
			password := c.Request.FormValue("password")
			fullname := c.Request.FormValue("fullname")

			if username == "" {
				err = fmt.Errorf("Username not specified")
			} else if password == "" {
				err = fmt.Errorf("Password not specified")
			} else {
				u := p.db.GetUser(username)
				if u == nil {
					if fullname == "" {
						fullname = username
					}
					if err = p.db.CreateUser(&db.UserProfile{
						UserName: username,
						FullName: fullname,
						Password: password,
						Enabled:  true,
						Role:     p.config.settings.DefaultRole,
					}); err == nil {
						c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
					}
				} else {
					err = fmt.Errorf("User already exist")
				}
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
		"allow_register": rt.serveTemplate == "session_login" && p.config.settings.SelfRegEnabled,
		"error":          err,
		"message":        message,
	})
	if rt.serveTemplate != "portal_session" || c.Request.URL.Path != "/logout" {
		c.Abort()
	}
}
