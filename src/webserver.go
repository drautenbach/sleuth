package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"sleuth/internal/db"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// A simple in-memory captive portal. It uses the client's IP address
// to gate access: unknown IPs are redirected to /captive where they
// can accept terms and be added to an allowlist for a short TTL.
type Portal struct {
	allowed map[string]time.Time
	mu      sync.RWMutex
	ttl     time.Duration
	router  *gin.Engine
	db      *db.Db
}

type Credentials struct {
	User     string
	Password string
}

func NewPortal(ttl time.Duration) *Portal {
	p := &Portal{
		allowed: make(map[string]time.Time),
		ttl:     ttl,
		router:  gin.Default(),
	}

	// register template functions before loading templates
	p.router.SetFuncMap(template.FuncMap{
		"title": func() template.HTML {
			return template.HTML(fmt.Sprintf("<title>%s</title>", "Sleuth"))
		},
		"array": func(values ...interface{}) []interface{} {
			return values
		},
	})

	p.router.Use(p.interceptHandler)
	p.router.Static("/lib", "www/lib")
	p.router.StaticFile("/login", "www/login")
	p.router.LoadHTMLGlob("templates/*")
	p.router.GET("/", p.serveTemplate)
	p.router.GET("/logout", p.logoutHandler)
	return p
}

func (p *Portal) isAllowed(c *gin.Context) bool {
	if c.Request.Method == http.MethodGet {
		info, err := os.Stat("./www" + c.Request.URL.Path)
		if info != nil && (os.IsExist(err) || !info.IsDir()) {
			return true
		}
	}
	ip := clientIP(c.Request)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if t, ok := p.allowed[ip]; ok {
		if p.ttl == 0 || time.Now().Before(t) {
			return true
		}
	}
	return false
}

func (p *Portal) allow(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ttl == 0 {
		// zero time means allowed indefinitely
		p.allowed[ip] = time.Time{}
	} else {
		p.allowed[ip] = time.Now().Add(p.ttl)
	}
}

func (p *Portal) serveTemplate(c *gin.Context) {
	p.HTML(c, strings.TrimPrefix(c.Request.URL.Path, "/"), nil)
}

func (p *Portal) HTML(c *gin.Context, path string, obj any) {
	// create a response map and merge any provided map-like object into it
	data := gin.H{}
	if path == "" {
		path = "index"
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
	data["nav"] = p.loadMenu(c)
	//data["path"] = path

	c.HTML(http.StatusOK, path+".html", data)
}

func (p *Portal) loadMenu(c *gin.Context) gin.H {
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
func (p *Portal) logoutHandler(c *gin.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ip := clientIP(c.Request)
	delete(p.allowed, ip)
	c.Redirect(http.StatusSeeOther, "/")
}

func (p *Portal) interceptHandler(c *gin.Context) {
	ip := clientIP(c.Request)
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
						p.allow(ip)
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
					p.HTML(c, "reset_password", gin.H{
						"username": c.Request.FormValue("username"),
						"next":     c.Query("next"),
						"error":    err,
					})
					c.Abort()
					return
				} else if u.Password == c.Request.FormValue("password") {
					p.allow(ip)
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

	p.HTML(c, "login", gin.H{
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

func WebServer(database *db.Db) {
	// TTL of 10 minutes for demonstration; set to 0 for indefinite
	portal := NewPortal(60 * time.Minute)
	portal.db = database

	wcSetupInit(portal)
	wcUsersInit(portal)
	wcProfilesInit(portal)
	webShellInit(portal)

	portal.router.Run(":80")
}
