package main

import (
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sleuth/internal/db"
	"sleuth/internal/log"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"golang.org/x/crypto/acme/autocert"
)

type proxyconfig struct {
	DomainName string
	URL        url.URL
	SSL        bool
	waf        coraza.WAF
	rp         *httputil.ReverseProxy
}

type HttpProxy struct {
	portal *Portal
	sites  map[string]proxyconfig
	Rules  []db.WafRule
	Errors map[string]error
}

func wcHttpProxyInit(portal *Portal) *HttpProxy {
	w := &HttpProxy{
		portal: portal,
	}
	var err error
	w.Rules, err = w.enumerateRules()
	if err != nil {
		log.Error(err)
	} else {
		for _, rule := range w.Rules {
			wr := w.portal.db.GetWafRule(rule.ID)
			if wr != nil {
				w.portal.db.UpdateWafRule(&rule)
			} else {
				w.portal.db.CreateWafRule(&rule)
			}
		}
	}

	if w.portal.db.GetWAFConfiguration("Default") == nil {
		w.portal.db.CreateWAFConfiguration(&db.WAFConfiguration{
			Name:    "Default",
			Raw:     "Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf",
			Enabled: true,
		})
	}

	return w
}

func (p *HttpProxy) ApplyConfiguration() error {
	sites := make(map[string]proxyconfig)
	wl := make([]string, 0)
	waf := make(map[string]coraza.WAF)
	var err error
	for _, wafconfig := range p.portal.db.GetWAFConfigurations() {
		if wafconfig.Enabled {
			waf[wafconfig.Name], err = coraza.NewWAF(coraza.NewWAFConfig().
				WithRootFS(coreruleset.FS).
				WithDirectives(wafconfig.Raw))
			if err != nil {
				p.Errors[wafconfig.Name] = err
			}
		}
	}

	for _, proxy := range p.portal.db.GetHTTPProxyConfigurations() {
		if proxy.Enabled {
			url, err := url.Parse(proxy.URL)
			if err == nil {
				rp := httputil.NewSingleHostReverseProxy(url)
				originalDirector := rp.Director
				rp.Director = func(req *http.Request) {
					originalDirector(req)
					// Forward the original Host header if needed:
					req.Host = url.Host
				}
				w := waf[proxy.WAFConfig]
				sites[proxy.DomainName] = proxyconfig{
					DomainName: proxy.DomainName,
					URL:        *url,
					SSL:        proxy.SSL,
					rp:         rp,
					waf:        w,
				}
				if proxy.SSL {
					wl = append(wl, proxy.DomainName)
				}
			} else {
				log.Error(err)
			}
		}
	}
	p.portal.certManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(wl...),
		Cache:      autocert.DirCache(".certs"), // folder to store certs
	}
	p.sites = sites

	return err
}

func (p *HttpProxy) WAFHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		site, rp := p.sites[r.Host]

		if r.URL.Scheme == "https" && (!rp || !site.SSL) {
			http.Redirect(w, r, "http://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}

		if r.URL.Scheme == "http" && rp && site.SSL {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}

		if rp {

			if site.waf != nil {
				tx := site.waf.NewTransaction()
				defer tx.ProcessLogging()

				incomingport := 80
				if site.SSL {
					incomingport = 443
				}
				outgoingport, _ := strconv.ParseInt(site.URL.Port(), 10, 64)
				if outgoingport == 0 {
					if site.URL.Scheme == "https" {
						outgoingport = 443
					} else {
						outgoingport = 80
					}
				}
				tx.ProcessConnection(site.DomainName, incomingport, site.URL.Host, int(outgoingport))
				tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

				for name, values := range r.Header {
					for _, value := range values {
						tx.AddRequestHeader(name, value)
					}
				}
				if r.ContentLength > 0 {
					tx.ProcessRequestBody()
				}

				if it := tx.ProcessRequestHeaders(); it != nil {
					http.Error(w, "Request blocked by WAF", http.StatusForbidden)
					return
				}
			}

			site.rp.ServeHTTP(w, r)

		} else {

			host := r.RemoteAddr
			if h, _, err := net.SplitHostPort(host); err == nil {
				if h == "127.0.0.1" || p.portal.db.GetSession(h) != nil {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "Invalid session", http.StatusForbidden)
		}

	})
}

var (
	idRe     = regexp.MustCompile(`id:(\d+)`)
	msgRe    = regexp.MustCompile(`msg:'([^']*)'`)
	tagRe    = regexp.MustCompile(`tag:'([^']*)'`)
	phaseRe  = regexp.MustCompile(`phase:(\d)`)
	actionRe = regexp.MustCompile(`(deny|block|pass|allow|drop|redirect)`)
)

func (p *HttpProxy) enumerateRules() ([]db.WafRule, error) {
	var rules []db.WafRule

	err := fs.WalkDir(coreruleset.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || !strings.HasSuffix(path, ".conf") {
			return nil
		}

		data, err := fs.ReadFile(coreruleset.FS, path)
		if err != nil {
			return err
		}

		blocks := splitSecRuleBlocks(string(data))

		for _, block := range blocks {
			if !strings.Contains(block, "SecRule") && !strings.Contains(block, "SecAction") {
				continue
			}

			rule := db.WafRule{
				File:     path,
				Raw:      strings.TrimSpace(block),
				IsSystem: true, // CRS rules are system rules
			}

			// ID
			if m := idRe.FindStringSubmatch(block); len(m) > 1 {
				id, _ := strconv.Atoi(m[1])
				rule.ID = id
			}

			// Message
			if m := msgRe.FindStringSubmatch(block); len(m) > 1 {
				rule.Message = m[1]
			}

			// Phase
			if m := phaseRe.FindStringSubmatch(block); len(m) > 1 {
				rule.Phase = m[1]
			}

			// Action
			if m := actionRe.FindStringSubmatch(block); len(m) > 1 {
				rule.Action = m[1]
			}

			// Tags (IMPORTANT: capture ALL)
			tagMatches := tagRe.FindAllStringSubmatch(block, -1)
			for _, t := range tagMatches {
				if len(t) > 1 {
					rule.Tags = append(rule.Tags, t[1])
				}
			}

			// Only keep real rules (must have ID)
			if rule.ID != 0 {
				rules = append(rules, rule)
			}
		}

		return nil
	})

	return rules, err
}

func splitSecRuleBlocks(input string) []string {
	var blocks []string
	var current strings.Builder

	lines := strings.Split(input, "\n")

	inRule := false

	for _, line := range lines {
		trim := strings.TrimSpace(line)

		if strings.HasPrefix(trim, "SecRule") || strings.HasPrefix(trim, "SecAction") {
			inRule = true
			current.Reset()
		}

		if inRule {
			current.WriteString(trim)
			current.WriteString(" ")

			// end of rule (no trailing backslash)
			if !strings.HasSuffix(trim, "\\") && strings.Contains(current.String(), "\"") {
				blocks = append(blocks, current.String())
				inRule = false
			}
		}
	}

	return blocks
}
