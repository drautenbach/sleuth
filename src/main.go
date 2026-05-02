package main

import (
	"sleuth/internal/db"
	"sleuth/internal/dns"
	"sleuth/internal/log"
	"time"
)

func main() {
	log.Info("Starting Sleuth %s...\n", AppVersion)

	p := InitPortal()
	d := dns.InitDnsServer(p.fw, p.security)
	initDefaults(p)

	defer p.db.Close()
	// start HTTP and DNS servers concurrently and keep main alive
	go p.server.router.Run("0.0.0.0:80")
	go d.Start()
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

	if len(p.db.GetDNSCategories()) == 0 && len(p.db.GetDNSRuleSets()) == 0 {
		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "fakenews",
			CategoryName: "Fake News",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-fakenews",
			CategoryId:  "fakenews",
			RuleSetName: "Steven Black FakeNews",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "gambling",
			CategoryName: "Gambling",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-gambling",
			CategoryId:  "gambling",
			RuleSetName: "Steven Black Gambling",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "adult",
			CategoryName: "Adult content",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-porn",
			CategoryId:  "adult",
			RuleSetName: "Steven Black Pornography",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "social",
			CategoryName: "Social Media",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-social",
			CategoryId:  "social",
			RuleSetName: "Steven Black Social Media",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "malicious",
			CategoryName: "Malicious sites",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-scams",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's Fake DNS Blocklist",
			Description: "Protects against internet scams, traps & fakes! Blocks fake stores, -streaming, rip-offs, cost traps and co.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "ads",
			CategoryName: "Ads & popups",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-ads",
			CategoryId:  "ads",
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Blocks annoying and malicious pop-up ads.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "ads",
			CategoryName: "Ads & popups",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-ads",
			CategoryId:  "ads",
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Blocks annoying and malicious pop-up ads.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "threats",
			CategoryName: "Threats",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tif",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Increases security significantly! Blocks Malware, Cryptojacking, Spam, Scam and Phishing.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "nrd",
			CategoryName: "Newly Registered Domains",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd7",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - Last 7 days",
			Description: "Domains from 7 days ago to yesterday (the last day)",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd7.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     false,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd8-14",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 8 to 14 days",
			Description: "Domains from 14 days ago to 8 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd14-8.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     false,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd15-21",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 15 to 21 days",
			Description: "Domains from 21 days ago to 15 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd21-15.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     false,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd22-28",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 22 to 28 days",
			Description: "Domains from 28 days ago to 22 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd28-22.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     false,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd29-35",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 29 to 35 days",
			Description: "Domains from 35 days ago to 29 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd35-29.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     false,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "bypass",
			CategoryName: "Bypassing services",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-network-bypass",
			CategoryId:  "bypass",
			RuleSetName: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass DNS Blocklist",
			Description: "Prevent methods to bypass your DNS, blocks encrypted DNS, VPN, TOR, Proxies.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-safesearch-bypass",
			CategoryId:  "bypass",
			RuleSetName: "HaGeZi's safesearch not supported DNS Blocklist",
			Description: "Prevents the use of search engines that do not support safesearch.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-safesearch-bypass",
			CategoryId:  "bypass",
			RuleSetName: "HaGeZi's safesearch not supported DNS Blocklist",
			Description: "Prevents the use of search engines that do not support safesearch.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-badware",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's Badware Hoster DNS Blocklist",
			Description: "Blocks known hosters that also host badware via user content to prevent the use of these hosters for malicious purposes.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tlds",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's The World's Most Abused TLDs - Aggressive",
			Description: "The Top Most Abused Top Level Domains",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "urlshortner",
			CategoryName: "URL Shortner Services",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-urlshortner",
			CategoryId:  "urlshortner",
			RuleSetName: "HaGeZi's Blocklist URL Shortener",
			Description: "This list blocks url shortener.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/urlshortener-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "piracy",
			CategoryName: "Pirated content",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-piracy",
			CategoryId:  "piracy",
			RuleSetName: "HaGeZi's Anti-Piracy DNS Blocklist",
			Description: "Blocks websites and services that are mainly used for illegal distribution of copyrighted content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "gambling",
			CategoryName: "Gambling",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-gambling",
			CategoryId:  "gambling",
			RuleSetName: "HaGeZi's Gambling DNS Blocklist",
			Description: "Blocks gambling content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-social",
			CategoryId:  "social",
			RuleSetName: "HaGeZi's Social Networks DNS Blocklist",
			Description: "Blocks access to social networks (Facebook, Instagram, TikTok, X (formerly Twitter), Snapchat, ...)",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nsfw",
			CategoryId:  "adult",
			RuleSetName: "HaGeZi's NSFW DNS Blocklist",
			Description: "Blocks adult content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "tracker",
			CategoryName: "Trackers",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-amazon",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Amazon Tracker DNS Blocklist",
			Description: "Blocks Amazon native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.amazon-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-apple",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Apple Tracker DNS Blocklist",
			Description: "Blocks Apple native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-huawei",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Huawei Tracker DNS Blocklist",
			Description: "Blocks Hauwei native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-winoffice",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Windows/Office Tracker DNS Blocklist",
			Description: "Blocks Windows/Office native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tiktok",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Tiktok Extended Tracker DNS Blocklist",
			Description: "Blocks Tiktok Extended native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok.extended-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-lgwebos",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's LG webOS Tracker DNS Blocklist",
			Description: "Blocks LG webOS native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.lgwebos-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-roku",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Roku Tracker DNS Blocklist",
			Description: "Blocks Roku native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.roku-onlydomains.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-abuse",
			CategoryId:  "malicious",
			RuleSetName: "Abuse Block List",
			Description: "Domains involved in abuse",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-ads",
			CategoryId:  "ads",
			RuleSetName: "Ads Block List",
			Description: "Ad serving domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-crypto",
			CategoryId:  "malicious",
			RuleSetName: "Crypto Block List",
			Description: "Cryptocurrency mining and scams",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-crypto",
			CategoryId:  "malicious",
			RuleSetName: "Crypto Block List",
			Description: "Cryptocurrency mining and scams",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "drugs",
			CategoryName: "Drugs",
			Enabled:      true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-drugs",
			CategoryId:  "drugs",
			RuleSetName: "Drugs Block List",
			Description: "Drug-related domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-facebook",
			CategoryId:  "social",
			RuleSetName: "Facebook/Meta Block List",
			Description: "Facebook and Meta domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/facebook-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-fraud",
			CategoryId:  "malicious",
			RuleSetName: "Fraud Block List",
			Description: "Fraud and scam domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-gambling",
			CategoryId:  "gambling",
			RuleSetName: "Gambling Block List",
			Description: "Gambling sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-malware",
			CategoryId:  "malicious",
			RuleSetName: "Malware Block List",
			Description: "Malware distribution domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-phishing",
			CategoryId:  "malicious",
			RuleSetName: "Phishing Block List",
			Description: "Phishing domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-piracy",
			CategoryId:  "piracy",
			RuleSetName: "Piracy Block List",
			Description: "Piracy and illegal streaming",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-porn",
			CategoryId:  "adult",
			RuleSetName: "Porn Block List",
			Description: "Adult content domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-ransomware",
			CategoryId:  "malicious",
			RuleSetName: "Ransomware Block List",
			Description: "Ransomware C2 and distribution",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-redirect",
			CategoryId:  "malicious",
			RuleSetName: "Redirect Block List",
			Description: "URL shorteners and redirects",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/redirect-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-scam",
			CategoryId:  "malicious",
			RuleSetName: "Scam Block List",
			Description: "Scam domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-tiktok",
			CategoryId:  "social",
			RuleSetName: "Tiktok Block List",
			Description: "TikTok domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/tiktok-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-torrent",
			CategoryId:  "piracy",
			RuleSetName: "Torrent Block List",
			Description: "Torrent and P2P sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-tracker",
			CategoryId:  "tracker",
			RuleSetName: "Tracking Block List",
			Description: "Tracking and analytics",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-twitter",
			CategoryId:  "social",
			RuleSetName: "Twitter Block List",
			Description: "Twitter/X domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/twitter-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-vaping",
			CategoryId:  "drugs",
			RuleSetName: "Vaping Block List",
			Description: "Vaping and e-cigarette sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/vaping-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

		p.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-whatsapp",
			CategoryId:  "social",
			RuleSetName: "Whatsapp Block List",
			Description: "WhatsApp domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/whatsapp-nl.txt",
			Schedule:    "0 23 * * *",
			Rules:       make([]string, 0),
			Enabled:     true,
			External:    true,
		})

	}
}
