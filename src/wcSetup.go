package main

import (
	"net/http"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
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

	return setup
}
