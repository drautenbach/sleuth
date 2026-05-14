package rules

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sleuth/internal/db"
	"slices"
	"strconv"
	"strings"
)

type DNSRulesEngine struct {
	db *db.Db
}

func Init(db *db.Db) *DNSRulesEngine {

	return &DNSRulesEngine{
		db: db,
	}
}

func (re *DNSRulesEngine) InitDefaults() {
	if len(re.db.GetDNSCategories()) == 0 && len(re.db.GetDNSRuleSets()) == 0 {
		fakenews := "Fake News"
		gambling := "Gambling"
		social := "Social Media"
		malicious := "Malicious sites"
		ads := "Ads & popups"
		threats := "Threats"
		nrd := "Newly Registered Domains"
		bypass := "Bypassing services"
		urlshortner := "URL Shortner Services"
		piracy := "Pirated content"
		trackers := "Trackers"
		drugs := "Drugs"

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: fakenews,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-fakenews",
			CategoryId:  re.db.FindDNSCategory(fakenews).CategoryId,
			RuleSetName: "Steven Black FakeNews",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
			Schedule:    "0 23 * * *",
			Enabled:     true,
			External:    true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: gambling,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-gambling",
			CategoryId:  re.db.FindDNSCategory(gambling).CategoryId,
			RuleSetName: "Steven Black Gambling",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		adult := "Adult content"
		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: adult,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-porn",
			CategoryId:  re.db.FindDNSCategory(adult).CategoryId,
			RuleSetName: "Steven Black Pornography",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: social,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-social",
			CategoryId:  re.db.FindDNSCategory(social).CategoryId,
			RuleSetName: "Steven Black Social Media",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: malicious,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-scams",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "HaGeZi's Fake DNS Blocklist",
			Description: "Protects against internet scams, traps & fakes! Blocks fake stores, -streaming, rip-offs, cost traps and co.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: ads,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-ads",
			CategoryId:  re.db.FindDNSCategory(ads).CategoryId,
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Blocks annoying and malicious pop-up ads.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: ads,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-ads",
			CategoryId:  re.db.FindDNSCategory(ads).CategoryId,
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Blocks annoying and malicious pop-up ads.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: threats,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tif",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Increases security significantly! Blocks Malware, Cryptojacking, Spam, Scam and Phishing.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: nrd,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd7",
			CategoryId:  re.db.FindDNSCategory(nrd).CategoryId,
			RuleSetName: "Newly Registered Domains (NRD) - Last 7 days",
			Description: "Domains from 7 days ago to yesterday (the last day)",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd7.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd8-14",
			CategoryId:  re.db.FindDNSCategory(nrd).CategoryId,
			RuleSetName: "Newly Registered Domains (NRD) - 8 to 14 days",
			Description: "Domains from 14 days ago to 8 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd14-8.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd15-21",
			CategoryId:  re.db.FindDNSCategory(nrd).CategoryId,
			RuleSetName: "Newly Registered Domains (NRD) - 15 to 21 days",
			Description: "Domains from 21 days ago to 15 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd21-15.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd22-28",
			CategoryId:  re.db.FindDNSCategory(nrd).CategoryId,
			RuleSetName: "Newly Registered Domains (NRD) - 22 to 28 days",
			Description: "Domains from 28 days ago to 22 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd28-22.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd29-35",
			CategoryId:  re.db.FindDNSCategory(nrd).CategoryId,
			RuleSetName: "Newly Registered Domains (NRD) - 29 to 35 days",
			Description: "Domains from 35 days ago to 29 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd35-29.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: bypass,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-network-bypass",
			CategoryId:  re.db.FindDNSCategory(bypass).CategoryId,
			RuleSetName: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass DNS Blocklist",
			Description: "Prevent methods to bypass your DNS, blocks encrypted DNS, VPN, TOR, Proxies.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-safesearch-bypass",
			CategoryId:  re.db.FindDNSCategory(bypass).CategoryId,
			RuleSetName: "HaGeZi's safesearch not supported DNS Blocklist",
			Description: "Prevents the use of search engines that do not support safesearch.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-safesearch-bypass",
			CategoryId:  re.db.FindDNSCategory(bypass).CategoryId,
			RuleSetName: "HaGeZi's safesearch not supported DNS Blocklist",
			Description: "Prevents the use of search engines that do not support safesearch.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-badware",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "HaGeZi's Badware Hoster DNS Blocklist",
			Description: "Blocks known hosters that also host badware via user content to prevent the use of these hosters for malicious purposes.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tlds",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "HaGeZi's The World's Most Abused TLDs - Aggressive",
			Description: "The Top Most Abused Top Level Domains",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: urlshortner,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-urlshortner",
			CategoryId:  re.db.FindDNSCategory(urlshortner).CategoryId,
			RuleSetName: "HaGeZi's Blocklist URL Shortener",
			Description: "This list blocks url shortener.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/urlshortener-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: piracy,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-piracy",
			CategoryId:  re.db.FindDNSCategory(piracy).CategoryId,
			RuleSetName: "HaGeZi's Anti-Piracy DNS Blocklist",
			Description: "Blocks websites and services that are mainly used for illegal distribution of copyrighted content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: gambling,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-gambling",
			CategoryId:  re.db.FindDNSCategory(gambling).CategoryId,
			RuleSetName: "HaGeZi's Gambling DNS Blocklist",
			Description: "Blocks gambling content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-social",
			CategoryId:  re.db.FindDNSCategory(social).CategoryId,
			RuleSetName: "HaGeZi's Social Networks DNS Blocklist",
			Description: "Blocks access to social networks (Facebook, Instagram, TikTok, X (formerly Twitter), Snapchat, ...)",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nsfw",
			CategoryId:  re.db.FindDNSCategory(adult).CategoryId,
			RuleSetName: "HaGeZi's NSFW DNS Blocklist",
			Description: "Blocks adult content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: trackers,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-amazon",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's Amazon Tracker DNS Blocklist",
			Description: "Blocks Amazon native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.amazon-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-apple",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's Apple Tracker DNS Blocklist",
			Description: "Blocks Apple native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-huawei",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's Huawei Tracker DNS Blocklist",
			Description: "Blocks Hauwei native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-winoffice",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's Windows/Office Tracker DNS Blocklist",
			Description: "Blocks Windows/Office native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tiktok",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's Tiktok Extended Tracker DNS Blocklist",
			Description: "Blocks Tiktok Extended native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok.extended-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-lgwebos",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's LG webOS Tracker DNS Blocklist",
			Description: "Blocks LG webOS native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.lgwebos-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-roku",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "HaGeZi's Roku Tracker DNS Blocklist",
			Description: "Blocks Roku native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.roku-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-abuse",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Abuse Block List",
			Description: "Domains involved in abuse",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-ads",
			CategoryId:  re.db.FindDNSCategory(ads).CategoryId,
			RuleSetName: "Ads Block List",
			Description: "Ad serving domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-crypto",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Crypto Block List",
			Description: "Cryptocurrency mining and scams",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-crypto",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Crypto Block List",
			Description: "Cryptocurrency mining and scams",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryName: drugs,
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-drugs",
			CategoryId:  re.db.FindDNSCategory(drugs).CategoryId,
			RuleSetName: "Drugs Block List",
			Description: "Drug-related domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-facebook",
			CategoryId:  re.db.FindDNSCategory(social).CategoryId,
			RuleSetName: "Facebook/Meta Block List",
			Description: "Facebook and Meta domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/facebook-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-fraud",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Fraud Block List",
			Description: "Fraud and scam domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-gambling",
			CategoryId:  re.db.FindDNSCategory(gambling).CategoryId,
			RuleSetName: "Gambling Block List",
			Description: "Gambling sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-malware",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Malware Block List",
			Description: "Malware distribution domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-phishing",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Phishing Block List",
			Description: "Phishing domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-piracy",
			CategoryId:  re.db.FindDNSCategory(piracy).CategoryId,
			RuleSetName: "Piracy Block List",
			Description: "Piracy and illegal streaming",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-porn",
			CategoryId:  re.db.FindDNSCategory(adult).CategoryId,
			RuleSetName: "Porn Block List",
			Description: "Adult content domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-ransomware",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Ransomware Block List",
			Description: "Ransomware C2 and distribution",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-redirect",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Redirect Block List",
			Description: "URL shorteners and redirects",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/redirect-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-scam",
			CategoryId:  re.db.FindDNSCategory(malicious).CategoryId,
			RuleSetName: "Scam Block List",
			Description: "Scam domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-tiktok",
			CategoryId:  re.db.FindDNSCategory(social).CategoryId,
			RuleSetName: "Tiktok Block List",
			Description: "TikTok domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/tiktok-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-torrent",
			CategoryId:  re.db.FindDNSCategory(piracy).CategoryId,
			RuleSetName: "Torrent Block List",
			Description: "Torrent and P2P sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-tracker",
			CategoryId:  re.db.FindDNSCategory(trackers).CategoryId,
			RuleSetName: "Tracking Block List",
			Description: "Tracking and analytics",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-twitter",
			CategoryId:  re.db.FindDNSCategory(social).CategoryId,
			RuleSetName: "Twitter Block List",
			Description: "Twitter/X domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/twitter-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-vaping",
			CategoryId:  re.db.FindDNSCategory(drugs).CategoryId,
			RuleSetName: "Vaping Block List",
			Description: "Vaping and e-cigarette sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/vaping-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-whatsapp",
			CategoryId:  re.db.FindDNSCategory(social).CategoryId,
			RuleSetName: "Whatsapp Block List",
			Description: "WhatsApp domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/whatsapp-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

	}
}

func isValidHostSourceRecord(split []string) bool {
	if len(split) == 0 {
		return false
	}
	if len(split) > 2 {
		return false
	}
	if len(split) == 2 {
		if split[0] != "0.0.0.0" {
			return false
		}
		if split[0] == "0.0.0.0" && split[1] == "0.0.0.0" {
			return false
		}
	}
	return true
}

func (re DNSRulesEngine) UpdateRuleSet(rs db.DNSRuleSet) error {
	if !rs.Enabled {
		return fmt.Errorf("Ruleset %s not enabled", rs.RuleSetName)
	}
	if rs.Source == "" {
		return fmt.Errorf("Ruleset %s source not specified", rs.RuleSetName)
	}

	data, err := getUrlData(rs.Source)
	if err != nil {
		return fmt.Errorf("Unable to fetch ruleset %s: %w", rs.RuleSetName, err)
	}

	var list = make([]string, 0)
	reader := bytes.NewReader(data)
	fileScanner := bufio.NewScanner(reader)
	fileScanner.Split(bufio.ScanLines)
	regex := regexp.MustCompile(`\s+`)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if line != "" && line[0] != '#' {
			split := regex.Split(line, -1)
			if isValidHostSourceRecord(split) {
				if len(split) == 2 {
					list = append(list, strings.ToLower(split[1])+".")
				} else if len(split) == 1 {
					list = append(list, strings.ToLower(split[0])+".")
				}
			}
		}
	}
	return re.db.UpdateDNSRules(&rs, &list)
}

func getUrlData(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("received invalid http response code " + strconv.Itoa(resp.StatusCode) + "for url " + url)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (re DNSRulesEngine) ReIndex() error {
	rs := re.db.GetDNSRuleSets()
	re.db.ClearDnsHostRules()
	for i := range rs {
		//		re.db.RemoveCategoryFromDnsHostRules(rs[i].CategoryId)
		rules := re.db.GetDNSRules(rs[i].RuleSetId)
		if rules != nil {
			for _, rule := range *rules {
				name := rule
				wildcard := false
				if name[:2] == "*." {
					wildcard = true
					name = rule[2:]
				}

				update := false
				hr := re.db.GetDnsHostRule(name)
				if hr == nil {
					hr = &db.DNSHostRule{
						Name:               name,
						WildcardCategories: make([]uint, 0),
						ExactCategories:    make([]uint, 0),
					}
				}
				if wildcard {
					if !slices.Contains(hr.WildcardCategories, rs[i].CategoryId) {
						update = true
						hr.WildcardCategories = append(hr.WildcardCategories, rs[i].CategoryId)
					}
				} else {
					if !slices.Contains(hr.ExactCategories, rs[i].CategoryId) {
						update = true
						hr.ExactCategories = append(hr.ExactCategories, rs[i].CategoryId)
					}
				}
				if update {
					re.db.SetDnsHostRule(hr)
				}
			}
		}
	}
	return nil
}

func (re DNSRulesEngine) Test(name string) []uint {
	matches := make([]uint, 0)
	parts := strings.Split(name, ".")
	for i := range parts {
		domain := strings.Join(parts[len(parts)-i-1:], ".")
		if domain != "" && domain != "." {
			hr := re.db.GetDnsHostRule(domain)
			if hr != nil {
				if i == len(parts)-1 {
					for _, cat := range hr.ExactCategories {
						if !slices.Contains(matches, cat) {
							matches = append(matches, cat)
						}
					}
				}
				for _, cat := range hr.WildcardCategories {
					if !slices.Contains(matches, cat) {
						matches = append(matches, cat)
					}
				}
			}
		}
	}
	return matches
}
