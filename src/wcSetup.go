package main

import (
	"github.com/gin-gonic/gin"
)

type wcSetup struct {
}

func wcSetupInit(p *Portal) *wcSetup {
	setup := &wcSetup{}

	p.router.GET("/settings", func(c *gin.Context) {
		p.HTML(c, "settings", gin.H{
			"model": gin.H{
				"enable_portal": true,
			},
		})
	})

	p.router.POST("/settings", func(c *gin.Context) {

	})

	return setup
}
