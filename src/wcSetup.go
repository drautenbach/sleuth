package main

import (
	"net/http"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
)

type wcSetup struct {
}

func wcSetupInit(p *Portal) *wcSetup {
	setup := &wcSetup{}

	p.router.GET("/settings", func(c *gin.Context) {
		p.HTML(c, "settings", gin.H{
			"model": p.config.settings,
			"roles": p.db.GetRoles(),
		})
	})

	p.router.POST("/settings", func(c *gin.Context) {
		mode, err := strconv.Atoi(c.PostForm("mode"))
		if err == nil {
			p.config.settings.DefaultRole = c.PostForm("default_role")
			p.config.settings.SelfRegEnabled = c.PostForm("self_reg_enabled") == "on"

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
				c.Redirect(http.StatusSeeOther, "/settings")
				c.Abort()
				return
			}
		}

		p.HTML(c, "settings", gin.H{
			"model": p.config.settings,
			"roles": p.db.GetRoles(),
			"err":   err,
		})
	})

	return setup
}
