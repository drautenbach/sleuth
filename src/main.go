package main

import "log"

func main() {
	log.Printf("Starting Sleuth %s...\n", AppVersion)
	GetConfig().ReadConfig()
	GetConfig().Print()
	initServer()
	//initBlacklistRenewal()
	// start HTTP and DNS servers concurrently and keep main alive
	go WebServer()
	//sgo DnsServer()
	select {}
}

func initServer() {
	initLogging()
	GetUpstreamCache().Init()
	//updateLocalRecords()
	//updateBlacklistRecords()
	//updateWhitelistRecords()
}
