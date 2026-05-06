package main

import (
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
	go p.server.router.Run("0.0.0.0:80")
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
