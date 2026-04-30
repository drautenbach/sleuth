package main

import (
	"fmt"
	"net/http"
	"sleuth/internal/db"

	"github.com/gin-gonic/gin"
)

type wcDnsConfig struct {
}

func wcDnsConfigInit(p *Portal) *wcDnsConfig {
	dc := &wcDnsConfig{}

	/**** Categories ****/

	p.server.router.GET("/dnsconfig/categories", func(c *gin.Context) {
		categories := p.db.GetDNSCategories()
		p.server.HTML(c, "dnsconfig_categories", gin.H{
			"model": gin.H{
				"Categories": categories,
			},
		})
	})

	p.server.router.GET("/dnsconfig/categories/new", func(c *gin.Context) {
		p.server.HTML(c, "dnsconfig_category", gin.H{
			"action": "create",
			"title":  "New DNS Category",
			"model": gin.H{
				"Category": make(map[string]interface{}),
			},
		})
	})

	p.server.router.POST("/dnsconfig/categories/new", func(c *gin.Context) {
		var cat = &db.DNSCategory{
			CategoryName: c.PostForm("categoryname"),
		}
		var err = p.db.CreateDNSCategory(cat)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/dnsconfig/categories")
			c.Abort()
		} else {
			p.server.HTML(c, "dnsconfig_category", gin.H{
				"action": "create",
				"title":  "New DNS Category",
				"error":  err.Error(),
				"model": gin.H{
					"Category": cat,
				},
			})
		}
	})

	p.server.router.GET("/dnsconfig/category/:categoryid", func(c *gin.Context) {
		categoryid := c.Param("categoryid")
		category := p.db.GetDNSCategory(categoryid)
		p.server.HTML(c, "dnsconfig_category", gin.H{
			"action": "edit",
			"title":  "Edit DNS Category",
			"model": gin.H{
				"Category": category,
			},
		})
	})

	p.server.router.POST("/dnsconfig/category/:categoryid", func(c *gin.Context) {
		var cat = p.db.GetDNSCategory(c.Param("categoryid"))
		var err error
		if cat == nil {
			err = fmt.Errorf("DNS category %s does not exist", c.Param("categoryid"))
		} else {
			cat.CategoryName = c.PostForm("categoryname")
			p.db.UpdateDNSCategory(cat)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/dnsconfig/categories")
			c.Abort()
		} else {
			p.server.HTML(c, "dnsconfig_category", gin.H{
				"action": "edit",
				"title":  "Edit DNS Category",
				"error":  err.Error(),
				"model": gin.H{
					"Category": cat,
				},
			})
		}
	})

	p.server.router.GET("/dnsconfig/categories/delete/:categoryid", func(c *gin.Context) {
		category := p.db.GetDNSCategory(c.Param("categoryid"))
		p.server.HTML(c, "dnsconfig_category_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Category",
			"model": gin.H{
				"Category": category,
			},
		})
	})

	p.server.router.POST("/dnsconfig/categories/delete/:categoryid", func(c *gin.Context) {
		err := p.db.DeleteDNSCategory(c.Param("categoryid"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/dnsconfig/categories")
			c.Abort()
		} else {
			category := p.db.GetDNSCategory(c.Param("categoryid"))
			p.server.HTML(c, "dnsconfig_category_delete", gin.H{
				"action": "delete",
				"title":  "Delete DNS Category",
				"error":  err.Error(),
				"model": gin.H{
					"Category": category,
				},
			})
		}
	})

	return dc
}
