package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sleuth/internal/log"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"golang.org/x/crypto/acme/autocert"
)

type proxyconfig struct {
	DomainName string
	URL        url.URL
	SSL        bool
	rp         *httputil.ReverseProxy
}

type HttpProxy struct {
	portal *Portal
	config coraza.WAFConfig
	waf    coraza.WAF
	sites  map[string]proxyconfig
}

func wcHttpProxyInit(portal *Portal) *HttpProxy {
	w := &HttpProxy{
		portal: portal,
	}

	return w
}

func (p *HttpProxy) ApplyConfiguration() error {
	sites := make(map[string]proxyconfig)
	wl := make([]string, 0)
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
				sites[proxy.DomainName] = proxyconfig{
					DomainName: proxy.DomainName,
					URL:        *url,
					SSL:        proxy.SSL,
					rp:         rp,
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
		Cache:      autocert.DirCache("certs"), // folder to store certs
	}
	p.sites = sites

	var err error
	p.config = coraza.NewWAFConfig()
	p.waf, err = coraza.NewWAF(p.config)
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
			tx := p.waf.NewTransaction()
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

			site.rp.ServeHTTP(w, r)

		} else {

			host := r.RemoteAddr
			if h, _, err := net.SplitHostPort(host); err == nil {
				s := p.portal.db.GetSession(h)
				if s != nil {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "Invalid session", http.StatusForbidden)
		}

	})
}
