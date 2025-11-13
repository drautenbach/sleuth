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
	"github.com/golang-jwt/jwt/v5"
)

type WebServer struct {
	ttl        time.Duration
	allowed    map[string]time.Time
	router     *gin.Engine
	mu         sync.RWMutex
	signingKey []byte
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
	/*s.mu.Lock()
	defer s.mu.Unlock()
	ip := clientIP(c.Request)
	delete(s.allowed, ip)*/

	c.SetCookie("sleuth_session", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/")
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

func (s *WebServer) isWebHost(hostname string) bool {
	if hostname == "127.0.0.1" {
		return true
	} else if ip := net.ParseIP(hostname); ip != nil {
		interfaces, err := net.Interfaces()
		if err != nil {
			return false
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
				if currentIP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

func (s *WebServer) isAllowed(c *gin.Context) bool {
	if c.Request.Method == http.MethodGet && s.isWebHost(c.Request.Host) {
		info, err := os.Stat("./www" + c.Request.URL.Path)
		if info != nil && (os.IsExist(err) || !info.IsDir()) {
			return true
		}
	}

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
		if _, err := s.ValidateSessionToken(tokenStr); err == nil {
			return true
		}
	}

	// 2) Fallback: legacy IP allowlist (kept for compatibility)
	ip := clientIP(c.Request)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.allowed[ip]; ok {
		if s.ttl == 0 || time.Now().Before(t) {
			return true
		}
	}
	return false
}

/*func (s *WebServer) allow(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ttl == 0 {
		// zero time means allowed indefinitely
		s.allowed[ip] = time.Time{}
	} else {
		s.allowed[ip] = time.Now().Add(s.ttl)
	}
}*/

// CreateSessionToken creates a signed JWT for the given username and returns token string and expiration time.
func (s *WebServer) CreateSessionToken(username string) (string, time.Time, error) {
	exp := time.Now().Add(s.ttl)
	claims := jwt.MapClaims{
		"username": username,
		"sub":      username,
		"exp":      jwt.NewNumericDate(exp),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.signingKey)
	return signed, exp, err
}

// ValidateSessionToken validates the token and returns the username from claims.
func (s *WebServer) ValidateSessionToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.signingKey, nil
	})
	if err != nil || !token.Valid {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims")
	}
	username, ok := claims["username"].(string)
	if !ok {
		// fallback to sub
		if sub, ok2 := claims["sub"].(string); ok2 {
			return sub, nil
		}
		return "", fmt.Errorf("missing username claim")
	}
	return username, nil
}
func initWebServer(ttl time.Duration, h gin.HandlerFunc) *WebServer {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev-secret-change-me"
	}
	s := &WebServer{
		allowed:    make(map[string]time.Time),
		router:     gin.Default(),
		ttl:        ttl,
		signingKey: []byte(secret),
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

	if h != nil {
		s.router.Use(h)
	}
	s.router.Static("/lib", "www/lib")
	s.router.StaticFile("/login", "www/admin_login")
	s.router.LoadHTMLGlob("templates/*")
	s.router.GET("/", s.serveTemplate)
	s.router.GET("/logout", s.logoutHandler)

	return s
}
