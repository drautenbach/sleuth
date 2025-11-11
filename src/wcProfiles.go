package main

import (
	"fmt"
	"net/http"
	"sleuth/internal/db"
	"time"

	"github.com/gin-gonic/gin"
)

type wcProfiles struct {
}

func wcProfilesInit(p *Portal) *wcProfiles {
	profiles := &wcProfiles{}

	p.server.router.GET("/profiles/users", func(c *gin.Context) {
		Users := p.db.GetUsers()
		p.server.HTML(c, "profiles_users", gin.H{
			"model": gin.H{
				"Users": Users,
			},
		})
	})

	p.server.router.GET("/profiles/users/new", func(c *gin.Context) {
		p.server.HTML(c, "profiles_user", gin.H{
			"action": "create",
			"title":  "New User",
			"model": gin.H{
				"User": make(map[string]interface{}),
			},
		})
	})

	p.server.router.POST("/profiles/users/new", func(c *gin.Context) {
		var u = &db.UserProfile{
			UserName:      c.PostForm("username"),
			FullName:      c.PostForm("fullname"),
			EmailAddress:  c.PostForm("emailaddress"),
			PasswordReset: time.Now().Add(24 * time.Hour),
			Enabled:       true,
			Role:          c.PostForm("role"),
		}
		var err = p.db.CreateUser(u)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			p.server.HTML(c, "profiles_user", gin.H{
				"action": "create",
				"title":  "New User",
				"error":  err.Error(),
				"model": gin.H{
					"User": u,
				},
			})
		}
	})

	p.server.router.GET("/profiles/user/:username", func(c *gin.Context) {
		// get username from the route parameter
		username := c.Param("username")
		User := p.db.GetUser(username)
		Roles := p.db.GetRoles()
		p.server.HTML(c, "profiles_user", gin.H{
			"action": "edit",
			"title":  "Edit User",
			"model": gin.H{
				"User":  User,
				"Roles": Roles,
			},
		})
	})

	p.server.router.POST("/profiles/user/:username", func(c *gin.Context) {
		var u = p.db.GetUser(c.Param("username"))
		var err error
		if u == nil {
			err = fmt.Errorf("user %s does not exist", c.Param("username"))
		} else {
			u.FullName = c.PostForm("fullname")
			u.EmailAddress = c.PostForm("emailaddress")
			u.Enabled = c.PostForm("enabled") == "on"
			u.Role = c.PostForm("role")
			p.db.UpdateUser(u)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			var roles = p.db.GetRoles()

			p.server.HTML(c, "profiles_user", gin.H{
				"action": "edit",
				"title":  "Edit User",
				"error":  err.Error(),
				"model": gin.H{
					"User":  u,
					"Roles": roles,
				},
			})
		}
	})

	p.server.router.GET("/profiles/users/delete/:username", func(c *gin.Context) {
		// get username from the route parameter
		User := p.db.GetUser(c.Param("username"))
		p.server.HTML(c, "profiles_user_delete", gin.H{
			"action": "delete",
			"title":  "Delete User",
			"model": gin.H{
				"User": User,
			},
		})
	})

	p.server.router.POST("/profiles/users/delete/:username", func(c *gin.Context) {
		// get username from the route parameter
		err := p.db.DeleteUser(c.Param("username"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			User := p.db.GetUser(c.Param("username"))
			p.server.HTML(c, "profiles_user_delete", gin.H{
				"action": "delete",
				"title":  "Delete User",
				"error":  err.Error(),
				"model": gin.H{
					"User": User,
				},
			})
		}
	})

	p.server.router.GET("/profiles/users/reset/:username", func(c *gin.Context) {
		// get username from the route parameter
		User := p.db.GetUser(c.Param("username"))
		p.server.HTML(c, "profiles_user_reset", gin.H{
			"action": "reset",
			"title":  "Reset User Password",
			"model": gin.H{
				"User": User,
			},
		})
	})

	p.server.router.POST("/profiles/users/reset/:username", func(c *gin.Context) {
		var u = p.db.GetUser(c.Param("username"))
		var err error
		if u == nil {
			err = fmt.Errorf("user %s does not exist", c.Param("username"))
		} else {
			u.PasswordReset = time.Now().Add(60 * time.Minute)
			p.db.UpdateUser(u)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/users")
			c.Abort()
		} else {
			p.server.HTML(c, "profiles_user_reset", gin.H{
				"action": "reset",
				"title":  "Reset User Password",
				"model": gin.H{
					"User": u,
				},
			})
		}
	})

	/**** Roles ****/

	p.server.router.GET("/profiles/roles", func(c *gin.Context) {
		roles := p.db.GetRoles()
		p.server.HTML(c, "profiles_roles", gin.H{
			"model": gin.H{
				"Roles": roles,
			},
		})
	})

	p.server.router.GET("/profiles/roles/new", func(c *gin.Context) {
		p.server.HTML(c, "profiles_role", gin.H{
			"action": "create",
			"title":  "New Role",
			"model": gin.H{
				"Role": make(map[string]interface{}),
			},
		})
	})

	p.server.router.POST("/profiles/roles/new", func(c *gin.Context) {
		var r = &db.Role{
			RoleName: c.PostForm("rolename"),
			Admin:    c.PostForm("admin") == "on",
		}
		var err = p.db.CreateRole(r)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/roles")
			c.Abort()
		} else {
			p.server.HTML(c, "profiles_role", gin.H{
				"action": "create",
				"title":  "New Role",
				"error":  err.Error(),
				"model": gin.H{
					"Role": r,
				},
			})
		}
	})

	p.server.router.GET("/profiles/role/:rolename", func(c *gin.Context) {
		// get rolename from the route parameter
		rolename := c.Param("rolename")
		role := p.db.GetRole(rolename)
		p.server.HTML(c, "profiles_role", gin.H{
			"action": "edit",
			"title":  "Edit Role",
			"model": gin.H{
				"Role": role,
			},
		})
	})

	p.server.router.POST("/profiles/role/:rolename", func(c *gin.Context) {
		var r = p.db.GetRole(c.Param("rolename"))
		var err error
		if r == nil {
			err = fmt.Errorf("role %s does not exist", c.Param("rolename"))
		} else {
			r.Admin = c.PostForm("admin") == "on"
			p.db.UpdateRole(r)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/roles")
			c.Abort()
		} else {
			p.server.HTML(c, "profiles_role", gin.H{
				"action": "edit",
				"title":  "Edit Role",
				"error":  err.Error(),
				"model": gin.H{
					"Role": r,
				},
			})
		}
	})

	p.server.router.GET("/profiles/roles/delete/:rolename", func(c *gin.Context) {
		// get rolename from the route parameter
		role := p.db.GetRole(c.Param("rolename"))
		p.server.HTML(c, "profiles_role_delete", gin.H{
			"action": "delete",
			"title":  "Delete Role",
			"model": gin.H{
				"Role": role,
			},
		})
	})

	p.server.router.POST("/profiles/roles/delete/:rolename", func(c *gin.Context) {
		// get rolename from the route parameter
		err := p.db.DeleteRole(c.Param("rolename"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/roles")
			c.Abort()
		} else {
			role := p.db.GetRole(c.Param("rolename"))
			p.server.HTML(c, "profiles_role_delete", gin.H{
				"action": "delete",
				"title":  "Delete Role",
				"error":  err.Error(),
				"model": gin.H{
					"Role": role,
				},
			})
		}
	})

	/**** Devices ****/

	p.server.router.GET("/profiles/devices", func(c *gin.Context) {
		devices := p.db.GetDevices()
		p.server.HTML(c, "profiles_devices", gin.H{
			"model": gin.H{
				"Devices": devices,
			},
		})
	})

	p.server.router.GET("/profiles/devices/new", func(c *gin.Context) {
		p.server.HTML(c, "profiles_device", gin.H{
			"action": "create",
			"title":  "New Device",
			"model": gin.H{
				"Device": make(map[string]interface{}),
				"Users":  p.db.GetUsers(),
			},
		})
	})

	p.server.router.POST("/profiles/devices/new", func(c *gin.Context) {
		var d = &db.DeviceProfile{
			MACAddress: c.PostForm("macaddress"),
			HostName:   c.PostForm("hostname"),
			UserName:   c.PostForm("username"),
			DeviceName: c.PostForm("devicename"),
		}
		var err = p.db.CreateDevice(d)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/devices")
			c.Abort()
		} else {
			p.server.HTML(c, "profiles_device", gin.H{
				"action": "create",
				"title":  "New Device",
				"error":  err.Error(),
				"model": gin.H{
					"Device": d,
					"Users":  p.db.GetUsers(),
				},
			})
		}
	})

	p.server.router.GET("/profiles/device/:macaddress", func(c *gin.Context) {
		// get rolename from the route parameter
		macaddress := c.Param("macaddress")
		p.server.HTML(c, "profiles_device", gin.H{
			"action": "edit",
			"title":  "Edit Device",
			"model": gin.H{
				"Device": p.db.GetDevice(macaddress),
				"Users":  p.db.GetUsers(),
			},
		})
	})

	p.server.router.POST("/profiles/device/:devicename", func(c *gin.Context) {
		var d = p.db.GetDevice(c.Param("devicename"))
		var err error
		if d == nil {
			err = fmt.Errorf("device %s does not exist", c.Param("devicename"))
		} else {
			d.HostName = c.PostForm("hostname")
			d.UserName = c.PostForm("username")
			d.DeviceName = c.PostForm("devicename")
			p.db.UpdateDevice(d)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/devices")
			c.Abort()
		} else {
			p.server.HTML(c, "profiles_device", gin.H{
				"action": "edit",
				"title":  "Edit Device",
				"error":  err.Error(),
				"model": gin.H{
					"Device": d,
					"Users":  p.db.GetUsers(),
				},
			})
		}
	})

	p.server.router.GET("/profiles/devices/delete/:macaddress", func(c *gin.Context) {
		// get macaddress from the route parameter
		device := p.db.GetDevice(c.Param("macaddress"))
		p.server.HTML(c, "profiles_device_delete", gin.H{
			"action": "delete",
			"title":  "Delete Device",
			"model": gin.H{
				"Device": device,
			},
		})
	})

	p.server.router.POST("/profiles/devices/delete/:macaddress", func(c *gin.Context) {
		// get devicename from the route parameter
		err := p.db.DeleteDevice(c.Param("macaddress"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/profiles/devices")
			c.Abort()
		} else {
			device := p.db.GetDevice(c.Param("devicename"))
			p.server.HTML(c, "profiles_device_delete", gin.H{
				"action": "delete",
				"title":  "Delete Device",
				"error":  err.Error(),
				"model": gin.H{
					"Device": device,
				},
			})
		}
	})

	return profiles
}
