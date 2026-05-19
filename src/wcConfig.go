package main

import (
	"fmt"
	"net/http"
	"reflect"
	"sleuth/internal/db"
	"strconv"
	"time"

	"sort"

	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
)

type wcConfig struct {
}

func wcConfigInit(p *Portal) *wcConfig {
	dc := &wcConfig{}

	/**** Categories ****/

	p.server.router.GET("/config/categories", func(c *gin.Context) {
		p.server.HTML(c, "config_dnscategories", gin.H{
			"model": gin.H{
				"Categories": p.rules.GetCategoryHierarchy(nil),
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
		category := p.db.GetDNSCategory(categoryid)
		p.server.HTML(c, "config_dnscategory", gin.H{
			"action": "edit",
			"title":  "Edit DNS Category",
			"model": gin.H{
				"Category": category,
			},
		})
	})

	p.server.router.POST("/config/category/:categoryid", func(c *gin.Context) {
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

	p.server.router.GET("/config/categories/delete/:categoryid", func(c *gin.Context) {
		category := p.db.GetDNSCategory(c.Param("categoryid"))
		p.server.HTML(c, "config_dnscategory_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Category",
			"model": gin.H{
				"Category": category,
			},
		})
	})

	p.server.router.POST("/config/categories/delete/:categoryid", func(c *gin.Context) {
		err := p.db.DeleteDNSCategory(c.Param("categoryid"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/categories")
			c.Abort()
		} else {
			category := p.db.GetDNSCategory(c.Param("categoryid"))
			p.server.HTML(c, "config_dnscategory_delete", gin.H{
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
			rs.CategoryId = c.PostForm("categoryid")
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
		hits := p.rules.Test(name + ".")
		duration := time.Since(now)

		allcats := p.db.GetDNSCategories()
		cats := make([]db.DNSCategory, 0)
		for _, hit := range hits {
			for _, cat := range allcats {
				if cat.CategoryId == hit {
					cats = append(cats, cat)
				}
			}
		}

		p.server.HTML(c, "rules_eval", gin.H{
			"action": "eval",
			"title":  "DNS rule evaluator",
			"model": gin.H{
				"name": name,
				"hits": cats,
				"stats": gin.H{
					"duration": duration.String(),
					"count":    len(hits),
				},
			},
		})

	})

	p.server.router.GET("/config/api", func(c *gin.Context) {

		apis := []map[string]any{}
		apis = append(apis, map[string]any{"api": "DomScan", "Enabled": p.config.settings.APIs.DomScan.Enabled})

		p.server.HTML(c, "config_apis", gin.H{
			"title": "API Configuration",
			"model": gin.H{
				"APIs": apis,
			},
		})
	})

	p.server.router.GET("/config/api/DomScan", func(c *gin.Context) {

		p.server.HTML(c, "config_api_domscan", gin.H{
			"title": "DomScan API Configuration",
			"model": p.config.settings.APIs.DomScan,
		})
	})

	p.server.router.POST("/config/api/DomScan", func(c *gin.Context) {

		var err error
		enabled := c.Request.FormValue("Enabled") == "on"
		WebSiteCategorization := c.Request.FormValue("WebSiteCategorization") == "on"
		key := c.Request.FormValue("Key")
		save := true
		if enabled {
			if key == "" {
				err = fmt.Errorf("Please enter an API key")
				save = false
			}
		}

		if save {
			p.config.settings.APIs.DomScan.Enabled = enabled
			p.config.settings.APIs.DomScan.Key = key
			p.config.settings.APIs.DomScan.Services.WebSiteCategorization = WebSiteCategorization
			err = p.db.SaveSettings(*p.config.settings)
			if err == nil {
				c.Redirect(http.StatusSeeOther, c.Request.RequestURI)
			}
		}

		p.server.HTML(c, "config_api_domsc", gin.H{
			"title": "API Configuration",
			"model": gin.H{
				"Enabled": enabled,
				"Key":     key,
				"Services": gin.H{
					"WebSiteCategorization": WebSiteCategorization,
				},
			},
			"error": err,
		})
	})

	/**** Profiles ****/

	type TypeStruct struct {
		Value int
		Text  string
	}

	types := []TypeStruct{
		{0, "UDP"},
		{1, "TCP"},
		{2, "TCP over TLS"},
	}

	p.server.router.GET("/config/dnsconfigurations", func(c *gin.Context) {
		profiles := p.db.GetDNSConfigurations()

		sort.Slice(profiles, func(i, j int) bool {
			return profiles[i].Name < profiles[j].Name
		})

		p.server.HTML(c, "config_dnsconfigurations", gin.H{
			"model": gin.H{
				"Profiles": profiles,
			},
		})
	})

	p.server.router.GET("/config/dnsconfigurations/new", func(c *gin.Context) {
		p.server.HTML(c, "config_dnsconfiguration", gin.H{
			"action": "create",
			"title":  "New DNS Configuration",
			"model": gin.H{
				"Profile": make(map[string]interface{}),
				"Types":   types,
			},
		})
	})

	p.server.router.POST("/config/dnsconfigurations/new", func(c *gin.Context) {

		var profile = &db.DNSConfiguration{
			Name:    c.PostForm("name"),
			Address: c.PostForm("address"),
		}

		t, err := strconv.Atoi(c.PostForm("type"))
		if err == nil {
			modeVal := reflect.ValueOf(t)

			rv := reflect.ValueOf(&profile.Type).Elem()

			if modeVal.Type().ConvertibleTo(rv.Type()) {
				rv.Set(modeVal.Convert(rv.Type()))
			} else if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
				rv.SetInt(int64(t))
			}

			err = p.db.CreateDNSConfiguration(profile)
		}
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/dnsconfigurations")
			c.Abort()
		} else {
			p.server.HTML(c, "config_dnsconfiguration", gin.H{
				"action": "create",
				"title":  "New DNS Configuration",
				"error":  err.Error(),
				"model": gin.H{
					"Profile": profile,
					"Types":   types,
				},
			})
		}
	})

	p.server.router.GET("/config/DNSConfiguration/:profileid", func(c *gin.Context) {
		profileid := c.Param("profileid")
		profile := p.db.GetDNSConfiguration(profileid)
		p.server.HTML(c, "config_dnsconfiguration", gin.H{
			"action": "edit",
			"title":  "Edit DNS Configuration",
			"model": gin.H{
				"Profile": profile,
				"Types":   types,
			},
		})
	})

	p.server.router.POST("/config/DNSConfiguration/:profileid", func(c *gin.Context) {
		var profile = p.db.GetDNSConfiguration(c.Param("profileid"))
		var err error
		if profile == nil {
			err = fmt.Errorf("DNS Configuration %s does not exist", c.Param("profileid"))
		} else {
			profile.Name = c.PostForm("name")
			profile.Address = c.PostForm("address")

			t, err := strconv.Atoi(c.PostForm("type"))
			if err == nil {
				modeVal := reflect.ValueOf(t)

				rv := reflect.ValueOf(&profile.Type).Elem()

				if modeVal.Type().ConvertibleTo(rv.Type()) {
					rv.Set(modeVal.Convert(rv.Type()))
				} else if rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64 {
					rv.SetInt(int64(t))
				}

				p.db.UpdateDNSConfiguration(profile)
			}
		}

		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/dnsconfigurations")
			c.Abort()
		} else {
			p.server.HTML(c, "config_dnsconfiguration", gin.H{
				"action": "edit",
				"title":  "Edit DNS Configuration",
				"error":  err.Error(),
				"model": gin.H{
					"Profile": profile,
					"Types":   types,
				},
			})
		}
	})

	p.server.router.GET("/config/dnsconfigurations/delete/:profileid", func(c *gin.Context) {
		profile := p.db.GetDNSConfiguration(c.Param("profileid"))
		p.server.HTML(c, "config_dnsconfiguration_delete", gin.H{
			"action": "delete",
			"title":  "Delete DNS Configuration",
			"model": gin.H{
				"Profile": profile,
			},
		})
	})

	p.server.router.POST("/config/dnsconfigurations/delete/:profileid", func(c *gin.Context) {
		err := p.db.DeleteDNSConfiguration(c.Param("profileid"))
		if err == nil {
			c.Redirect(http.StatusSeeOther, "/config/dnsconfigurations")
			c.Abort()
		} else {
			profile := p.db.GetDNSConfiguration(c.Param("profileid"))
			p.server.HTML(c, "config_dnsconfiguration_delete", gin.H{
				"action": "delete",
				"title":  "Delete DNS Configuration",
				"error":  err.Error(),
				"model": gin.H{
					"Profile": profile,
				},
			})
		}
	})

	return dc
}
