package main

import (
	"fmt"
	"time"
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
			EmailAddress: c.PostForm("emailaddress"),
			PasswordReset: time.Now().Add(24 * time.Hour),
			Enabled: true,
			Admin: c.PostForm("admin") == "on",
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
		var u = p.db.GetUser(c.Param("username"))
		var err error
		if (u == nil) {
			err = fmt.Errorf("user %s does not exist", c.Param("username"))
		} else {
			u.FullName = c.PostForm("fullname")
			u.EmailAddress = c.PostForm("emailaddress")
			u.Enabled = c.PostForm("enabled") == "on"
			u.Admin = c.PostForm("admin") == "on"
			p.db.UpdateUser(u)
		}
	
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

	p.router.GET("/profiles/users/delete/:username", func(c *gin.Context) {
		// get username from the route parameter
		User := p.db.GetUser(c.Param("username"))
		p.HTML(c, "profiles_user_delete", gin.H{
			"action": "delete",
			"title":  "Delete User",
			"model": gin.H{
				"User": User,
			},
		})
	})

	p.router.POST("/profiles/users/delete/:username", func(c *gin.Context) {
		// get username from the route parameter
		err := p.db.DeleteUser(c.Param("username"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			User := p.db.GetUser(c.Param("username"))
			p.HTML(c, "profiles_user_delete", gin.H{
				"action": "delete",
				"title":  "Delete User",
				"error":  err.Error(),
				"model": gin.H{
					"User": User,
				},
			})
		}
	})

	p.router.GET("/profiles/users/reset/:username", func(c *gin.Context) {
		// get username from the route parameter
		User := p.db.GetUser(c.Param("username"))
		p.HTML(c, "profiles_user_reset", gin.H{
			"action": "reset",
			"title":  "Reset User Password",
			"model": gin.H{
				"User": User,
			},
		})
	})

	p.router.POST("/profiles/users/reset/:username", func(c *gin.Context) {
		var u = p.db.GetUser(c.Param("username"))
		var err error
		if (u == nil) {
			err = fmt.Errorf("user %s does not exist", c.Param("username"))
		} else {
			u.PasswordReset = time.Now().Add(10 * time.Minute)
			p.db.UpdateUser(u)
		}
	
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			p.HTML(c, "profiles_user_reset", gin.H{
				"action": "reset",
				"title":  "Reset User Password",
				"model": gin.H{
					"User": u,
				},
			})
		}
	})


	return profiles
}
