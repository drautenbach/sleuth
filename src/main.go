package main

import (
	"crypto/tls"
	"net/http"
	"sleuth/internal/db"
	"sleuth/internal/log"
	"time"
)

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)
	p := InitPortal()
	initDefaults(p)

	defer p.db.Close()
	// start HTTP and DNS servers concurrently and keep main alive

	go func() {
		httpsServer := &http.Server{
			Addr: ":443",
			TLSConfig: &tls.Config{
				GetCertificate: p.certManager.GetCertificate,
			},
			Handler: p.certManager.HTTPHandler(p.redirectHandler(p.server.router)),
		}
		log.Print("HTTPS server running on port 443")
		log.Error(httpsServer.ListenAndServeTLS("", "")) // certificates handled automatically
	}()

	go func() {
		httpServer := &http.Server{
			Addr:    ":80",
			Handler: p.certManager.HTTPHandler(p.redirectHandler(p.server.router)),
		}
		log.Print("HTTP server running on port 80")
		log.Error(httpServer.ListenAndServe())
	}()

	go p.dns.Start()
	select {}
}

func initDefaults(p *Portal) {
	if len(p.db.GetRoles()) == 0 {
		r := &db.Role{
			RoleName:   "admin",
			SystemRole: true,
			Admin:      true,
		}
		p.db.CreateRole(r)

		r = &db.Role{
			RoleName:   "user",
			SystemRole: true,
			Admin:      false,
		}
		p.db.CreateRole(r)

		r = &db.Role{
			RoleName:   "guest",
			SystemRole: true,
			Admin:      false,
		}
		p.db.CreateRole(r)
	}

	if len(p.db.GetUsers()) == 0 {
		up := &db.UserProfile{
			UserName:      "admin",
			Password:      "admin",
			Role:          "admin",
			Enabled:       true,
			PasswordReset: time.Now().Add(time.Hour * 72),
		}
		p.db.CreateUser(up)
	}

}
