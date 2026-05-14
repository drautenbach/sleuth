package main

import (
	"fmt"
	"net/http"
	"sleuth/internal/db"
	"strconv"
	"time"

	"sort"

	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
)

type wcDnsConfig struct {
}

func wcDnsConfigInit(p *Portal) *wcDnsConfig {
	dc := &wcDnsConfig{}

	/**** Categories ****/

	p.server.router.GET("/config/categories", func(c *gin.Context) {
		categories := p.db.GetDNSCategories()
		p.server.HTML(c, "config_dnscategories", gin.H{
			"model": gin.H{
				"Categories": categories,
			},
		})
	})

	p.server.router.GET("/config/categories/new", func(c *gin.Context) {
		p.server.HTML(c, "config_dnscategory", gin.H{
			"action": "create",
			"title":  "New DNS Category",
			"model": gin.H{
				"Category": make(map[string]interface{}),
			},
		})
	})

	p.server.router.POST("/config/categories/new", func(c *gin.Context) {
		var cat = &db.DNSCategory{
			CategoryName: c.PostForm("categoryname"),
			Enabled:      c.PostForm("enabled") == "on",
		}
		var err = p.db.CreateDNSCategory(cat)
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/categories")
			c.Abort()
		} else {
			p.server.HTML(c, "config_dnscategory", gin.H{
				"action": "create",
				"title":  "New DNS Category",
				"error":  err.Error(),
				"model": gin.H{
					"Category": cat,
				},
			})
		}
	})

	p.server.router.GET("/config/category/:categoryid", func(c *gin.Context) {
		categoryid := c.Param("categoryid")
		category := p.db.FindDNSCategory(categoryid)
		p.server.HTML(c, "config_dnscategory", gin.H{
			"action": "edit",
			"title":  "Edit DNS Category",
			"model": gin.H{
				"Category": category,
			},
		})
	})

	p.server.router.POST("/config/category/:categoryid", func(c *gin.Context) {
		var cat = p.db.FindDNSCategory(c.Param("categoryid"))
		var err error
		if cat == nil {
			err = fmt.Errorf("DNS category %s does not exist", c.Param("categoryid"))
		} else {
			cat.CategoryName = c.PostForm("categoryname")
			cat.Enabled = c.PostForm("enabled") == "on"
			p.db.UpdateDNSCategory(cat)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/categories")
			c.Abort()
		} else {
			p.server.HTML(c, "config_dnscategory", gin.H{
				"action": "edit",
				"title":  "Edit DNS Category",
				"error":  err.Error(),
				"model": gin.H{
					"Category": cat,
				},
			})
		}
	})

	p.server.router.GET("/config/categories/delete/:category", func(c *gin.Context) {
		category := p.db.FindDNSCategory(c.Param("category"))
		p.server.HTML(c, "config_dnscategory_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Category",
			"model": gin.H{
				"Category": category,
			},
		})
	})

	p.server.router.POST("/config/categories/delete/:category", func(c *gin.Context) {
		cat := p.db.FindDNSCategory(c.Param("category"))
		var err error
		if cat != nil {
			err = p.db.DeleteDNSCategory(cat.CategoryId)
			if err == nil {
				c.Redirect(http.StatusSeeOther, "/config/categories")
				c.Abort()
				return
			}
		} else {
			err = fmt.Errorf("Could not locate category %s", c.Param("category"))
		}

		p.server.HTML(c, "config_dnscategory_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Category",
			"error":  err.Error(),
			"model": gin.H{
				"Category": cat,
			},
		})

	})

	/**** RuleSets ****/

	rulesets := func(c *gin.Context, err error) {
		categories := p.db.GetDNSCategories()
		categoryMap := make(map[uint]string)
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
				rulesets[i].CategoryName = categoryName
			}
		}

		sort.Slice(rulesets, func(i, j int) bool {
			if rulesets[i].CategoryId != rulesets[j].CategoryId {
				return rulesets[i].CategoryId < rulesets[j].CategoryId
			}
			return rulesets[i].RuleSetName < rulesets[j].RuleSetName
		})

		p.server.HTML(c, "config_dnsrulesets", gin.H{
			"model": gin.H{
				"RuleSets": rulesets,
				"error":    err,
			},
		})
	}

	p.server.router.GET("/config/rulesets", func(c *gin.Context) { rulesets(c, nil) })

	p.server.router.POST("/config/rulesets", func(c *gin.Context) {
		action := c.Request.FormValue("action")

		if action == "reindex" {
			p.rules.ReIndex()
			c.Redirect(http.StatusSeeOther, c.Request.RequestURI)
			return
		} else {
			rulesetid := c.Request.FormValue("RuleSetId")
			if rulesetid == "" {
				rsets := p.db.GetDNSRuleSets()
				for i := range rsets {
					if rsets[i].Enabled && rsets[i].Source != "" {
						err := p.rules.UpdateRuleSet(rsets[i])
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
					rulesets(c, p.rules.UpdateRuleSet(*rs))
				}
			}
		}
	})

	p.server.router.GET("/config/rulesets/new", func(c *gin.Context) {
		p.server.HTML(c, "config_dnsruleset", gin.H{
			"action": "create",
			"title":  "New DNS rule set",
			"model": gin.H{
				"RuleSet":    make(map[string]interface{}),
				"Categories": p.db.GetDNSCategories(),
			},
		})
	})

	p.server.router.POST("/config/rulesets/new", func(c *gin.Context) {
		var ruleset = &db.DNSRuleSet{
			RuleSetName: c.PostForm("rulesetname"),
			CategoryId:  str2uint(c.PostForm("categoryid")),
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
			c.Redirect(http.StatusSeeOther, "/config/rulesets")
			c.Abort()
		} else {
			p.server.HTML(c, "config_dnsruleset", gin.H{
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

	p.server.router.GET("/config/ruleset/:rulesetid", func(c *gin.Context) {
		rulesetid := c.Param("rulesetid")
		ruleset := p.db.GetDNSRuleSet(rulesetid)
		p.server.HTML(c, "config_dnsruleset", gin.H{
			"action": "edit",
			"title":  "Edit DNS rule set",
			"model": gin.H{
				"RuleSet":    ruleset,
				"Categories": p.db.GetDNSCategories(),
			},
		})
	})

	p.server.router.POST("/config/ruleset/:rulesetid", func(c *gin.Context) {
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
			rs.CategoryId = str2uint(c.PostForm("categoryid"))
			rs.Source = c.PostForm("source")
			rs.Schedule = c.PostForm("schedule")
			rs.Enabled = c.PostForm("enabled") == "on"
			rs.External = c.PostForm("external") == "on"
			p.db.UpdateDNSRuleSet(rs)
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/rulesets")
			c.Abort()
		} else {
			p.server.HTML(c, "config_dnscategory", gin.H{
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

	p.server.router.GET("/config/rulesets/delete/:rulesetid", func(c *gin.Context) {
		ruleset := p.db.GetDNSRuleSet(c.Param("rulesetid"))
		p.server.HTML(c, "config_dnscategory_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Category",
			"model": gin.H{
				"RuleSet": ruleset,
			},
		})
	})

	p.server.router.POST("/config/rulesets/delete/:rulesetid", func(c *gin.Context) {
		err := p.db.DeleteDNSRuleSet(c.Param("rulesetid"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/rulesets")
			c.Abort()
		} else {
			ruleset := p.db.GetDNSRuleSet(c.Param("rulesetid"))
			p.server.HTML(c, "config_dnsruleset_delete", gin.H{
				"action": "delete",
				"title":  "Delete DNS rule set",
				"error":  err.Error(),
				"model": gin.H{
					"RuleSet": ruleset,
				},
			})
		}
	})

	p.server.router.GET("/rules/eval", func(c *gin.Context) {
		p.server.HTML(c, "rules_eval", gin.H{
			"action": "eval",
			"title":  "DNS rule evaluator",
			"model": gin.H{
				"Name": "",
			},
		})
	})

	p.server.router.POST("/rules/eval", func(c *gin.Context) {
		name := c.Request.FormValue("name")
		now := time.Now()

		duration := time.Since(now)
		hits := p.rules.Test(name + ".")
		p.server.HTML(c, "rules_eval", gin.H{
			"action": "eval",
			"title":  "DNS rule evaluator",
			"model": gin.H{
				"name": name,
				"hits": hits,
				"stats": gin.H{
					"duration": duration.String(),
					"count":    len(hits),
				},
			},
		})

	})

	return dc
}

func str2uint(str string) uint {
	i, _ := strconv.ParseUint(str, 10, 64)
	return uint(i)
}
