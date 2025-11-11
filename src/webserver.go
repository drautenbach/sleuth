package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type WebServer struct {
	ttl     time.Duration
	allowed map[string]time.Time
	router  *gin.Engine
	mu      sync.RWMutex
}

type Credentials struct {
	User     string
	Password string
}

func (s *WebServer) serveTemplate(c *gin.Context) {
	s.HTML(c, strings.TrimPrefix(c.Request.URL.Path, "/"), nil)
}

func (s *WebServer) HTML(c *gin.Context, path string, obj any) {
	// create a response map and merge any provided map-like object into it
	data := gin.H{}
	if path == "" {
		path = "admin_index"
	}

	if obj != nil {
		switch v := obj.(type) {
		case gin.H:
			for k, val := range v {
				data[k] = val
			}
		case map[string]any:
			for k, val := range v {
				data[k] = val
			}
		}
	}

	// set common fields
	data["context"] = c
	data["nav"] = s.loadMenu(c)
	//data["path"] = path

	c.HTML(http.StatusOK, path+".html", data)
}

func (s *WebServer) loadMenu(c *gin.Context) gin.H {
	data, err := os.ReadFile("templates/template-menu.json")
	if err != nil {
		return nil
	}
	var menu []map[string]interface{}
	if err := json.Unmarshal(data, &menu); err != nil {
		return nil
	}

	var markActive func(items map[string]interface{}) bool
	hierarchy := []map[string]interface{}{}
	markActive = func(item map[string]interface{}) bool {
		isActive := false

		// Check current item's href
		if href, ok := item["href"].(string); ok {
			if c != nil && c.Request != nil {
				if c.Request.URL.Path == href || (href != "/" && strings.HasPrefix(c.Request.URL.Path+"/", href)) {
					item["active"] = true
					isActive = true
				}
			}
		}

		// Check items array
		if items, ok := item["items"].([]interface{}); ok {
			for _, subItem := range items {
				if mapItem, ok := subItem.(map[string]interface{}); ok {
					if markActive(mapItem) {
						isActive = true
					}
				}
			}
		}

		if isActive {
			hierarchy = append([]map[string]interface{}{item}, hierarchy...)
			item["active"] = true
		}
		return isActive
	}

	// Process the menu
	for _, item := range menu {
		markActive(item)
	}

	return gin.H{
		"hierarchy": hierarchy,
		"menu":      menu,
	}
}

// ServeHTTP is middleware that checks the client IP and redirects
// to the captive portal when necessary.
func (s *WebServer) logoutHandler(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip := clientIP(c.Request)
	delete(s.allowed, ip)
	c.Redirect(http.StatusSeeOther, "/")
}

func (p *Portal) interceptHandler(c *gin.Context) {
	ip := clientIP(c.Request)
	if p.server.isAllowed(c) {
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
						p.server.allow(ip)
						c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
						return
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
					p.server.allow(ip)
					c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
					return
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

func clientIP(r *http.Request) string {
	// prefer X-Forwarded-For if present (first value)
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		parts := strings.Split(f, ",")
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func GetMACAddress(ip string) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var currentIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				currentIP = v.IP
			case *net.IPAddr:
				currentIP = v.IP
			}
			if currentIP.String() == ip {
				return iface.HardwareAddr.String()
			}
		}
	}
	return ""
}

func (s *WebServer) allow(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ttl == 0 {
		// zero time means allowed indefinitely
		s.allowed[ip] = time.Time{}
	} else {
		s.allowed[ip] = time.Now().Add(s.ttl)
	}
}

func initWebServer(ttl time.Duration) WebServer {
	s := &WebServer{
		allowed: make(map[string]time.Time),
		router:  gin.Default(),
		ttl:     ttl,
	}
	// register template functions before loading templates
	s.router.SetFuncMap(template.FuncMap{
		"title": func() template.HTML {
			return template.HTML(fmt.Sprintf("<title>%s</title>", "Sleuth"))
		},
		"array": func(values ...interface{}) []interface{} {
			return values
		},
	})

	s.router.Static("/lib", "www/lib")
	s.router.StaticFile("/login", "www/admin_login")
	s.router.LoadHTMLGlob("templates/*")
	s.router.GET("/", s.serveTemplate)
	s.router.GET("/logout", s.logoutHandler)

	return *s
}
