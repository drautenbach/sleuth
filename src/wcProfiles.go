package main

import (
	"fmt"
	"net/http"
	"reflect"
	"sleuth/internal/db"
	"strconv"
	"strings"
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
				"User":  make(map[string]interface{}),
				"Roles": p.db.GetRoles(),
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
					"User":  u,
					"Roles": p.db.GetRoles(),
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
		dns := p.db.GetDNSConfigurations()
		dmap := make(map[string]db.DNSConfiguration)
		for _, d := range dns {
			dmap[d.ProfileId] = d
		}
		for i := range roles {
			if roles[i].DNSOverride && roles[i].DNSAddress != "" {
				roles[i].DNSConfiguration = roles[i].DNSAddress
				if roles[i].DNSMode == 0 {
					roles[i].DNSPrependDeviceName = false
				}
			} else if dnsconfig, ok := dmap[roles[i].DNSConfiguration]; ok && dnsconfig.Address != "" {
				roles[i].DNSConfiguration = dnsconfig.Address
				if dnsconfig.Type == 0 {
					roles[i].DNSPrependDeviceName = false
				}
			} else {
				roles[i].DNSConfiguration = p.db.GetSettings().FallbackDNS
				roles[i].DNSPrependDeviceName = false
			}

		}

		p.server.HTML(c, "profiles_roles", gin.H{
			"model": gin.H{
				"Roles": roles,
			},
		})
	})

	type TypeStruct struct {
		Value int
		Text  string
	}

	types := []TypeStruct{
		{0, "UDP"},
		{1, "TCP"},
		{2, "TCP over TLS"},
	}

	p.server.router.GET("/profiles/roles/new", func(c *gin.Context) {
		p.server.HTML(c, "profiles_role", gin.H{
			"action": "create",
			"title":  "New Role",
			"model": gin.H{
				"Role":              &db.Role{},
				"DNSConfigurations": p.db.GetDNSConfigurations(),
				"Types":             types,
			},
		})
	})

	p.server.router.POST("/profiles/roles/new", func(c *gin.Context) {
		var err error
		var role = &db.Role{
			RoleName:             c.PostForm("rolename"),
			Admin:                c.PostForm("admin") == "on",
			DynamicRouting:       c.PostForm("dynamicrouting") == "on",
			DNSOverride:          c.PostForm("DNSOverride") == "on",
			DNSPrependDeviceName: c.PostForm("DNSPrependDeviceName") == "on",
			DNSConfiguration:     c.PostForm("DNSConfiguration"),
			DNSAddress:           strings.Trim(c.PostForm("DNSAddress"), " "),
		}
		t, err := strconv.Atoi(c.PostForm("DNSMode"))
		if err == nil {
			modeVal := reflect.ValueOf(t)

			rv := reflect.ValueOf(&role.DNSMode).Elem()

			if modeVal.Type().ConvertibleTo(rv.Type()) {
				rv.Set(modeVal.Convert(rv.Type()))
			} else if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
				rv.SetInt(int64(t))
			}
		}
		if !role.DNSOverride {
			dnsconfiguration := p.db.GetDNSConfiguration(role.DNSConfiguration)
			if dnsconfiguration != nil {
				role.DNSMode = dnsconfiguration.Type
				role.DNSAddress = dnsconfiguration.Address
			}
		}

		if c.PostForm("action") == "Create" {
			err = p.db.CreateRole(role)
			if err == nil {
				c.Redirect(http.StatusSeeOther, "/profiles/roles")
				c.Abort()
				return
			}
		}

		p.server.HTML(c, "profiles_role", gin.H{
			"action": "create",
			"title":  "New Role",
			"error":  err,
			"model": gin.H{
				"Role":              role,
				"DNSConfigurations": p.db.GetDNSConfigurations(),
				"Types":             types,
			},
		})
	})

	p.server.router.GET("/profiles/role/:rolename", func(c *gin.Context) {
		// get rolename from the route parameter
		rolename := c.Param("rolename")
		role := p.db.GetRole(rolename)
		if role != nil && !role.DNSOverride {
			dnsconfiguration := p.db.GetDNSConfiguration(role.DNSConfiguration)
			if dnsconfiguration != nil {
				role.DNSMode = dnsconfiguration.Type
				role.DNSAddress = dnsconfiguration.Address
			}
		}

		p.server.HTML(c, "profiles_role", gin.H{
			"action": "edit",
			"title":  "Edit Role",
			"model": gin.H{
				"Role":              role,
				"DNSConfigurations": p.db.GetDNSConfigurations(),
				"Types":             types,
			},
		})
	})

	p.server.router.POST("/profiles/role/:rolename", func(c *gin.Context) {
		var role = p.db.GetRole(c.Param("rolename"))

		role.Admin = c.PostForm("admin") == "on"
		role.DynamicRouting = c.PostForm("dynamicrouting") == "on"
		role.DNSOverride = c.PostForm("DNSOverride") == "on"
		role.DNSPrependDeviceName = c.PostForm("DNSPrependDeviceName") == "on"
		role.DNSConfiguration = c.PostForm("DNSConfiguration")
		role.DNSAddress = strings.Trim(c.PostForm("DNSAddress"), " ")

		t, err := strconv.Atoi(c.PostForm("DNSMode"))
		if err == nil {
			modeVal := reflect.ValueOf(t)

			rv := reflect.ValueOf(&role.DNSMode).Elem()

			if modeVal.Type().ConvertibleTo(rv.Type()) {
				rv.Set(modeVal.Convert(rv.Type()))
			} else if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
				rv.SetInt(int64(t))
			}
		}

		if !role.DNSOverride {
			dnsconfiguration := p.db.GetDNSConfiguration(role.DNSConfiguration)
			if dnsconfiguration != nil {
				role.DNSMode = dnsconfiguration.Type
				role.DNSAddress = dnsconfiguration.Address
			}
		}

		if role == nil {
			err = fmt.Errorf("role %s does not exist", c.Param("rolename"))
		} else if c.PostForm("action") == "edit" {
			err = p.db.UpdateRole(role)
			if err == nil {
				c.Redirect(http.StatusSeeOther, "/profiles/roles")
				c.Abort()
				return
			}
		}

		p.server.HTML(c, "profiles_role", gin.H{
			"action": "edit",
			"title":  "Edit Role",
			"error":  err,
			"model": gin.H{
				"Role":              role,
				"DNSConfigurations": p.db.GetDNSConfigurations(),
				"Types":             types,
			},
		})
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
			Enabled:    c.PostForm("enabled") == "true",
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
		device := p.db.GetDevice(macaddress)

		if device != nil {
			p.server.HTML(c, "profiles_device", gin.H{
				"action":    "edit",
				"title":     "Edit Device",
				"actionUrl": "/profiles/device/" + macaddress,
				"model": gin.H{
					"Device": p.db.GetDevice(macaddress),
					"Users":  p.db.GetUsers(),
				},
			})
		} else {
			deviceName := ""
			node := p.network.FindByMac(macaddress)
			if node != nil {
				if node.Mdns != "" {
					deviceName = node.Mdns
				}
				if node.Nbns != "" {
					deviceName = node.Nbns
				}
				if node.Dns != "" {
					deviceName = node.Dns
				}
			}
			hostname := deviceName
			if hostname == "" {
				hostname = "Unknown"
			}
			device = &db.DeviceProfile{
				MACAddress: macaddress,
				DeviceName: deviceName,
				HostName:   hostname,
			}
			p.server.HTML(c, "profiles_device", gin.H{
				"action":    "create",
				"actionUrl": "/profiles/devices/new",
				"title":     "New Device",
				"model": gin.H{
					"Device": device,
					"Users":  p.db.GetUsers(),
				},
			})
		}
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
			d.Enabled = c.PostForm("enabled") == "true"
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
