package main

import (
	"net/http"
	"sleuth/internal/db"

	"github.com/gin-gonic/gin"
)

type wcProfiles struct {
}

func wcProfilesInit(p *Portal) *wcProfiles {
	profiles := &wcProfiles{}
	p.router.GET("/profiles/users", func(c *gin.Context) {
		Users := p.db.GetUsers()
		p.HTML(c, "profiles_users", gin.H{
			"model": gin.H{
				"Users": Users,
			},
		})
	})

	p.router.GET("/profiles/users/new", func(c *gin.Context) {
		p.HTML(c, "profiles_user", gin.H{
			"action": "create",
			"title":  "New User",
			"model": gin.H{
				"User": make(map[string]interface{}),
			},
		})
	})

	p.router.POST("/profiles/users/new", func(c *gin.Context) {
		var u = &db.UserProfile{
			UserName: c.PostForm("username"),
			FullName: c.PostForm("fullname"),
		}
		var err = p.db.CreateUser(u)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			p.HTML(c, "profiles_user", gin.H{
				"action": "create",
				"title":  "New User",
				"error":  err.Error(),
				"model": gin.H{
					"User": u,
				},
			})
		}
	})

	// use a named param for the username (no wildcard with empty name)
	p.router.GET("/profiles/user/:username", func(c *gin.Context) {
		// get username from the route parameter
		username := c.Param("username")
		User := p.db.GetUser(username)
		p.HTML(c, "profiles_user", gin.H{
			"action": "edit",
			"title":  "Edit User",
			"model": gin.H{
				"User": User,
			},
		})
	})

	p.router.POST("/profiles/user/:username", func(c *gin.Context) {
		var u = &db.UserProfile{
			UserName: c.Param("username"),
			FullName: c.PostForm("fullname"),
		}
		var err = p.db.UpdateUser(u)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			p.HTML(c, "profiles_user", gin.H{
				"action": "edit",
				"title":  "Edit User",
				"error":  err.Error(),
				"model": gin.H{
					"User": u,
				},
			})
		}
	})

	return profiles
}
