package main

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme/autocert"
)

type wcSetup struct {
	portal *Portal
}

func (s *wcSetup) render(c *gin.Context, err error) {
	firewalls := s.portal.fw.AvailableFirewalls()
	found := false
	for _, m := range firewalls {
		if m == s.portal.config.settings.Firewall {
			found = true
			break
		}
	}
	if !found {
		s.portal.config.settings.Firewall = "default"
	}

	s.portal.server.HTML(c, "settings", gin.H{
		"model":     s.portal.config.settings,
		"roles":     s.portal.db.GetRoles(),
		"firewalls": firewalls,
		"err":       err,
	})
}

func (s *wcSetup) renderSSL(c *gin.Context, err error) {
	s.portal.server.HTML(c, "config_ssl", gin.H{
		"model": s.portal.config.settings.SSL,
		"error": err,
	})
}

func wcSetupInit(p *Portal) *wcSetup {
	setup := &wcSetup{portal: p}

	p.server.router.GET("/settings", func(c *gin.Context) {
		setup.render(c, nil)
	})

	p.server.router.POST("/settings", func(c *gin.Context) {
		mode, err := strconv.Atoi(c.PostForm("mode"))
		if err == nil {
			p.config.settings.DefaultRole = c.PostForm("default_role")
			p.config.settings.SelfRegEnabled = c.PostForm("self_reg_enabled") == "on"
			setfw := c.PostForm("firewall") != p.config.settings.Firewall
			p.config.settings.Firewall = c.PostForm("firewall")
			p.config.settings.FallbackDNS = c.PostForm("FallbackDNS")

			// convert int to the enum type stored in p.config.settings.Mode using reflection
			rv := reflect.ValueOf(&p.config.settings.Mode).Elem()
			modeVal := reflect.ValueOf(mode)
			if modeVal.Type().ConvertibleTo(rv.Type()) {
				rv.Set(modeVal.Convert(rv.Type()))
			} else if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
				rv.SetInt(int64(mode))
			}

			err = p.db.SaveSettings(*p.config.settings)

			if err == nil {
				if setfw {
					p.fw.SetActiveFirewall(p.config.settings.Firewall)
				}
				c.Redirect(http.StatusSeeOther, "/settings")
				c.Abort()
				return
			}
		}

		setup.render(c, err)
	})

	p.server.router.GET("/config/ssl", func(c *gin.Context) {
		setup.renderSSL(c, nil)
	})

	p.server.router.POST("/config/ssl", func(c *gin.Context) {
		action := c.Request.FormValue("action")
		domain := c.Request.FormValue("domain")
		index := slices.Index(p.config.settings.SSL, domain)

		var err error
		switch action {
		case "add":
			if index == -1 {
				p.config.settings.SSL = append(p.config.settings.SSL, domain)
			} else {
				err = fmt.Errorf("%s already in the list of domains", domain)
			}
		case "delete":
			if index == -1 {
				err = fmt.Errorf("Could not find %s in list of domains to remove", domain)
			} else {
				p.config.settings.SSL = slices.Delete(p.config.settings.SSL, index, index+1)
			}
		}
		if err == nil {
			err = p.db.SaveSettings(*p.config.settings)
		}
		if err == nil {
			p.certManager.HostPolicy = autocert.HostWhitelist(p.config.settings.SSL...)
			c.Redirect(http.StatusSeeOther, c.Request.RequestURI)
		} else {
			setup.renderSSL(c, err)
		}
	})

	return setup
}
