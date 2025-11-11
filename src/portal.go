package main

// A simple in-memory captive portal. It uses the client's IP address
// to gate access: unknown IPs are redirected to /captive where they
// can accept terms and be added to an allowlist for a short TTL.

import (
	"net/http"
	"os"
	"time"

	"sleuth/internal/db"

	"github.com/gin-gonic/gin"
)

type Portal struct {
	db     *db.Db
	server WebServer
	config GlobalConfiguration
}

func InitPortal() *Portal {
	p := &Portal{
		server: initWebServer(60 * time.Minute),
	}
	p.server.router.Use(p.interceptHandler)

	p.db = db.InitDB("./.data/")
	p.config = GlobalConfiguration{
		settings: p.db.GetSettings(),
	}

	wcSetupInit(p)
	wcUsersInit(p)
	wcProfilesInit(p)
	webShellInit(p)

	return p
}

func (s *WebServer) isAllowed(c *gin.Context) bool {
	if c.Request.Method == http.MethodGet {
		info, err := os.Stat("./www" + c.Request.URL.Path)
		if info != nil && (os.IsExist(err) || !info.IsDir()) {
			return true
		}
	}
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
