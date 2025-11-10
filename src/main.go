package main

import (
	"sleuth/internal/db"
	"sleuth/internal/log"
)

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)
	d := db.InitDB("./.data/")
	if len(d.GetRoles()) == 0 {
		r := &db.Role{
			RoleName:   "admin",
			SystemRole: true,
			Admin:      true,
		}
		d.CreateRole(r)

		r = &db.Role{
			RoleName:   "user",
			SystemRole: true,
			Admin:      false,
		}
		d.CreateRole(r)

		r = &db.Role{
			RoleName:   "guest",
			SystemRole: true,
			Admin:      false,
		}
		d.CreateRole(r)
	}

	if len(d.GetUsers()) == 0 {
		up := &db.UserProfile{
			UserName: "admin",
			Password: "admin",
			Role:     "admin",
			Enabled:  true,
		}
		d.CreateUser(up)
	}
	defer d.Close()
	GetConfig().ReadConfig()
	GetConfig().Print()
	initServer()
	initBlacklistRenewal()
	// start HTTP and DNS servers concurrently and keep main alive
	go WebServer(d)
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
