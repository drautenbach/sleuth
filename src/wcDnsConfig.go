package main

import (
	"fmt"
	"net/http"
	"sleuth/internal/db"

	"sort"

	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
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
			Enabled:      c.PostForm("enabled") == "on",
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
			cat.Enabled = c.PostForm("enabled") == "on"
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

	/**** RuleSets ****/

	rulesets := func(c *gin.Context, err error) {
		categories := p.db.GetDNSCategories()
		categoryMap := make(map[string]string)
		for _, category := range categories {
			categoryMap[category.CategoryId] = category.CategoryName
		}

		rulesets := p.db.GetDNSRuleSets()
		for i := range rulesets {
			if rulesets[i].External == false {
				rulesets[i].Source = ""
				rulesets[i].Schedule = "Manual"
			}
			if rulesets[i].Enabled == false && rulesets[i].Schedule != "" {
				rulesets[i].Schedule = "Disabled"
			}
			if categoryName, exists := categoryMap[rulesets[i].CategoryId]; exists {
				rulesets[i].CategoryId = categoryName
			}
		}

		sort.Slice(rulesets, func(i, j int) bool {
			if rulesets[i].CategoryId != rulesets[j].CategoryId {
				return rulesets[i].CategoryId < rulesets[j].CategoryId
			}
			return rulesets[i].RuleSetName < rulesets[j].RuleSetName
		})

		p.server.HTML(c, "dnsconfig_rulesets", gin.H{
			"model": gin.H{
				"RuleSets": rulesets,
				"error":    err,
			},
		})
	}

	p.server.router.GET("/dnsconfig/rulesets", func(c *gin.Context) { rulesets(c, nil) })

	p.server.router.POST("/dnsconfig/rulesets", func(c *gin.Context) {
		rulesetid := c.Request.FormValue("RuleSetId")
		if rulesetid == "" {
			rsets := p.db.GetDNSRuleSets()
			for i := range rsets {
				if rsets[i].Enabled && rsets[i].Source != "" {
					err := p.security.UpdateRuleSet(rsets[i])
					if err != nil {
						rulesets(c, err)
						return
					}

				}
			}
			rulesets(c, nil)
		} else {
			rs := p.db.GetDNSRuleSet(rulesetid)
			if rs == nil {
				rulesets(c, fmt.Errorf("Ruleset %s not found", c.Request.FormValue("RuleSetId")))
			} else {
				rulesets(c, p.security.UpdateRuleSet(*rs))
			}
		}
	})

	p.server.router.GET("/dnsconfig/rulesets/new", func(c *gin.Context) {
		p.server.HTML(c, "dnsconfig_ruleset", gin.H{
			"action": "create",
			"title":  "New DNS rule set",
			"model": gin.H{
				"RuleSet":    make(map[string]interface{}),
				"Categories": p.db.GetDNSCategories(),
			},
		})
	})

	p.server.router.POST("/dnsconfig/rulesets/new", func(c *gin.Context) {
		var ruleset = &db.DNSRuleSet{
			RuleSetName: c.PostForm("rulesetname"),
			CategoryId:  c.PostForm("categoryid"),
			Source:      c.PostForm("source"),
			Schedule:    c.PostForm("schedule"),
			Enabled:     c.PostForm("enabled") == "on",
			External:    c.PostForm("external") == "on",
		}

		var err error = nil
		if ruleset.Schedule != "" {
			_, err = cron.ParseStandard(ruleset.Schedule)
			if err != nil {
				err = fmt.Errorf("Update schedule: %w", err)
			}
		}

		if err == nil {
			err = p.db.CreateDNSRuleSet(ruleset)
		}
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/dnsconfig/rulesets")
			c.Abort()
		} else {
			p.server.HTML(c, "dnsconfig_ruleset", gin.H{
				"action": "create",
				"title":  "New DNS rule set",
				"error":  err.Error(),
				"model": gin.H{
					"RuleSet":    ruleset,
					"Categories": p.db.GetDNSCategories(),
				},
			})
		}
	})

	p.server.router.GET("/dnsconfig/ruleset/:rulesetid", func(c *gin.Context) {
		rulesetid := c.Param("rulesetid")
		ruleset := p.db.GetDNSRuleSet(rulesetid)
		p.server.HTML(c, "dnsconfig_ruleset", gin.H{
			"action": "edit",
			"title":  "Edit DNS rule set",
			"model": gin.H{
				"RuleSet":    ruleset,
				"Categories": p.db.GetDNSCategories(),
			},
		})
	})

	p.server.router.POST("/dnsconfig/ruleset/:rulesetid", func(c *gin.Context) {
		var rs = p.db.GetDNSRuleSet(c.Param("rulesetid"))
		var err error
		if rs == nil {
			err = fmt.Errorf("DNS rule set %s does not exist", c.Param("rulesetid"))
		}

		if err == nil && rs.Schedule != "" {
			_, err = cron.ParseStandard(rs.Schedule)
			if err != nil {
				err = fmt.Errorf("Update schedule: %w", err)
			}
		}

		if err == nil {
			rs.RuleSetName = c.PostForm("rulesetname")
			rs.CategoryId = c.PostForm("categoryid")
			rs.Source = c.PostForm("source")
			rs.Schedule = c.PostForm("schedule")
			rs.Enabled = c.PostForm("enabled") == "on"
			rs.External = c.PostForm("external") == "on"
			p.db.UpdateDNSRuleSet(rs)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/dnsconfig/rulesets")
			c.Abort()
		} else {
			p.server.HTML(c, "dnsconfig_category", gin.H{
				"action": "edit",
				"title":  "Edit DNS Category",
				"error":  err.Error(),
				"model": gin.H{
					"RuleSet":    rs,
					"Categories": p.db.GetDNSCategories(),
				},
			})
		}
	})

	p.server.router.GET("/dnsconfig/rulesets/delete/:rulesetid", func(c *gin.Context) {
		ruleset := p.db.GetDNSCategory(c.Param("rulesetid"))
		p.server.HTML(c, "dnsconfig_category_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Category",
			"model": gin.H{
				"RuleSet": ruleset,
			},
		})
	})

	p.server.router.POST("/dnsconfig/rulesets/delete/:rulesetid", func(c *gin.Context) {
		err := p.db.DeleteDNSRuleSet(c.Param("rulesetid"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/dnsconfig/rulesets")
			c.Abort()
		} else {
			ruleset := p.db.GetDNSCategory(c.Param("rulesetid"))
			p.server.HTML(c, "dnsconfig_ruleset_delete", gin.H{
				"action": "delete",
				"title":  "Delete DNS rule set",
				"error":  err.Error(),
				"model": gin.H{
					"RuleSet": ruleset,
				},
			})
		}
	})

	return dc
}
