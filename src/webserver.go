package main

import (
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
	path := strings.TrimPrefix(c.Request.URL.Path, "/")
	if path == "" {
		path = "index"
	}
	c.HTML(http.StatusOK, path+".html", gin.H{
		"title": "Sleuth",
	})
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

	if c.Request.Method == http.MethodPost && c.Request.FormValue("sleuth_action") != "" {
		var action = c.Request.FormValue("sleuth_action")
		switch action {
		case "login":
			u := p.db.GetUser(c.Request.FormValue("username"))
			if u != nil {
				if u.Password == c.Request.FormValue("password") {
					p.allow(ip)
					c.Redirect(http.StatusSeeOther, c.Request.URL.Path)
					return
				}
			}
		}

	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Sleuth",
		"next":  c.Query("next"),
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
	portal := NewPortal(10 * time.Minute)
	portal.db = database
	wcUsersInit(portal)
	webShellInit(portal)
	portal.router.Run(":80")
}
