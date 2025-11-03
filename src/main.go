package main

import "sleuth/internal/log"

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)
	GetConfig().ReadConfig()
	GetConfig().Print()
	initServer()
	initBlacklistRenewal()
	// start HTTP and DNS servers concurrently and keep main alive
	go WebServer()
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
