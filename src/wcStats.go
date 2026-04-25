package main

import (
	"sleuth/internal/constants"
	"sleuth/internal/firewall"

	"github.com/gin-gonic/gin"
)

type wcStats struct {
	portal *Portal
}

type trafficStat struct {
	Host   string
	IP     string
	TempIP string
}

func (s *wcStats) GetTrafficStats(ip string) []trafficStat {
	stats := []constants.FwdRule{}
	if len(ip) > 0 {
		stats = s.portal.db.GetFwdRulesByClient(ip)
	}

	var result []trafficStat
	for _, fr := range stats {
		neighbour := trafficStat{
			Host:   fr.Hostname,
			IP:     fr.OrigIP,
			TempIP: firewall.IP4fromOffset(fr.DestIPOffset),
		}
		result = append(result, neighbour)
	}
	return result
}

func (s *wcStats) renderTraffic(c *gin.Context, err error) {
	ip := c.Param("ip")
	if len(c.Request.URL.Query().Get("ip")) > 1 {
		c.Redirect(302, "/stats/traffic/"+c.Request.URL.Query().Get("ip"))
		return
	}

	s.portal.server.HTML(c, "stats_traffic", gin.H{
		"IP":    ip,
		"stats": s.GetTrafficStats(ip),
		"err":   err,
	})
}

func wcStatsInit(p *Portal) *wcStats {
	stats := &wcStats{portal: p}

	p.server.router.GET("/stats/traffic/:ip", func(c *gin.Context) {
		stats.renderTraffic(c, nil)
	})

	return stats
}
