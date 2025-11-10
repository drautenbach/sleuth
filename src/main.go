package main

import (
	"sleuth/internal/db"
	"sleuth/internal/log"
	"time"
)

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)
	GetConfig().ReadConfig()
	GetConfig().Print()

	p := NewPortal(60 * time.Minute)
	p.db = db.InitDB("./.data/")
	p.config = GlobalConfiguration{
		settings: p.db.GetSettings(),
	}

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
	initServer()
	initBlacklistRenewal()
	// start HTTP and DNS servers concurrently and keep main alive
	initWebServer(p)
	go p.router.Run(":80")
	go DnsServer()
	select {}
}

func initServer() {
	initLogging()
	GetUpstreamCache().Init()
	updateLocalRecords()
	updateBlacklistRecords()
	updateWhitelistRecords()
}
