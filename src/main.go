package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"sleuth/internal/db"
	logger "sleuth/internal/log"
	"strings"
	"time"
)

func main() {
	logger.Info("Starting Sleuth %s...\n", AppVersion)
	p := InitPortal()

	defer p.db.Close()
	// start HTTP and DNS servers concurrently and keep main alive

	go func() {
		httpsServer := &http.Server{
			Addr: ":443",
			TLSConfig: &tls.Config{
				GetCertificate: p.certManager.GetCertificate,
			},
			Handler:  p.certManager.HTTPHandler(p.httpproxy.WAFHandler(p.server.router)),
			ErrorLog: log.New(&filteredLogger{logger: log.Default()}, "", log.LstdFlags),
		}
		logger.Print("Starting HTTPS server running on port 443")
		err := httpsServer.ListenAndServe()
		logger.Printf("HTTP server exited: %v", err)
	}()

	go func() {
		httpServer := &http.Server{
			Addr: ":80",
			Handler: p.certManager.HTTPHandler(
				p.httpproxy.WAFHandler(p.server.router),
			),
		}

		logger.Print("Starting HTTP server on :80")

		err := httpServer.ListenAndServe()
		logger.Printf("HTTP server exited: %v", err)
	}()

	go p.dns.Start()
	select {}
}

func initDefaults(p *Portal) {
	if len(p.db.GetDNSConfigurations()) == 0 {
		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "NextDNS Default Profile (TLS)",
			Type:    db.ModeTLS,
			Address: "dns.nextdns.io",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "NextDNS (UDP)",
			Type:    db.ModeUDP,
			Address: "45.90.28.153",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "CleanBrowsing",
			Type:    db.ModeUDP,
			Address: "185.228.168.9",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "Cisco OpenDNS FamilyShield",
			Type:    db.ModeUDP,
			Address: "208.67.222.123",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "DNS4EU (unfiltered)",
			Type:    db.ModeUDP,
			Address: "86.54.11.100",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "DNS4EU (protective)",
			Type:    db.ModeUDP,
			Address: "86.54.11.1",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "DNS4EU (Protective + Child Protection)",
			Type:    db.ModeUDP,
			Address: "86.54.11.12",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "DNS4EU (Protective + Ad Blocking)",
			Type:    db.ModeUDP,
			Address: "86.54.11.13",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "DNS4EU (Protective + Child Protection + Ad Blocking)",
			Type:    db.ModeUDP,
			Address: "86.54.11.11",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "Quad9 (Malware/Phishing)",
			Type:    db.ModeUDP,
			Address: "9.9.9.9",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "Cloudflare (unfiltered)",
			Type:    db.ModeUDP,
			Address: "1.1.1.1",
		})

		p.db.CreateDNSConfiguration(&db.DNSConfiguration{
			Name:    "Cloudflare (family)",
			Type:    db.ModeUDP,
			Address: "1.1.1.3",
		})
	}

	if len(p.db.GetAccessProfiles()) == 0 {
		p.db.CreateAccessProfile(&db.AccessProfile{Name: "Default"})
	}

	if len(p.db.GetRoles()) == 0 {

		dnsconfigurations := p.db.GetDNSConfigurations()
		profile := dnsconfigurations[0]
		for i := range dnsconfigurations {
			if dnsconfigurations[i].Name == "NextDNS Default Profile (TLS)" {
				profile = dnsconfigurations[i]
			}
		}

		r := &db.Role{
			RoleName:         "admin",
			SystemRole:       true,
			Admin:            true,
			DynamicRouting:   false,
			DNSConfiguration: profile.ProfileId,
		}
		p.db.CreateRole(r)

		r = &db.Role{
			RoleName:         "user",
			SystemRole:       true,
			Admin:            false,
			DynamicRouting:   true,
			DNSConfiguration: profile.ProfileId,
		}
		p.db.CreateRole(r)

		r = &db.Role{
			RoleName:         "guest",
			SystemRole:       true,
			Admin:            false,
			DynamicRouting:   true,
			DNSConfiguration: profile.ProfileId,
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

	if p.config.settings.FallbackDNS == "" {
		p.config.settings.FallbackDNS = "1.1.1.3"
		p.db.SaveSettings(*p.config.settings)
	}

	if p.config.settings.LocalDomain == "" {
		p.config.settings.LocalDomain = "home"
		p.db.SaveSettings(*p.config.settings)
	}

}

type filteredLogger struct {
	logger *log.Logger
}

func (f *filteredLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "acme/autocert: host") &&
		strings.Contains(msg, "not configured in HostWhitelist") {
		// ignore this message
		return len(p), nil
	}
	return f.logger.Writer().Write(p)
}
