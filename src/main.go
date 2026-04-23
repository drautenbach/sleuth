package main

import (
	"sleuth/internal/db"
	"sleuth/internal/dns"
	"sleuth/internal/log"
)

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)

	p := InitPortal()
	d := dns.InitDnsServer(p.fw)

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
			UserName: "admin",
			Password: "admin",
			Role:     "admin",
			Enabled:  true,
		}
		p.db.CreateUser(up)
	}
	defer p.db.Close()
	// start HTTP and DNS servers concurrently and keep main alive
	go p.server.router.Run("0.0.0.0:8080")
	go d.Start()
	select {}
}
