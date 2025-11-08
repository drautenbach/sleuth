package main

import (
	"sleuth/internal/db"
	"sleuth/internal/log"
)

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)
	d := db.InitDB("./.data/")
	if len(d.GetUsers()) == 0 {
		up := &db.UserProfile{
			UserName: "admin",
			Password: "admin",
			Enabled:  true,
			Admin:    true,
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
