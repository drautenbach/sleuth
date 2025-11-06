package main

import (
	"github.com/gin-gonic/gin"
)

type wcProfiles struct {
}

func wcProfileUsersInit(p *Portal) *wcProfiles {
	profiles := &wcProfiles{}
	p.router.GET("/profiles/users", func(c *gin.Context) {
		Users := p.db.GetUsers()
		p.HTML(c, "profiles_users", gin.H{
			"model": gin.H{
				"Users": Users,
			},
		})
	})
	return profiles
}
