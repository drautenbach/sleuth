package main

import (
	"fmt"
	"sleuth/internal/constants"
	"sleuth/internal/firewall"

	"github.com/gin-gonic/gin"
)

type wcStats struct {
	portal *Portal
}

type trafficStat struct {
	Since    string
	Host     string
	IP       string
	TempIP   string
	Bytes    uint64
	Duration string
}

func (s *wcStats) GetTrafficStats(ip string) []trafficStat {
	stats := []constants.FwdRule{}
	if len(ip) > 0 {
		stats = s.portal.db.GetFwdRulesByClient(ip)
	}

	var result []trafficStat
	for _, fr := range stats {
		duration := fr.Until.Sub(fr.Since)
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		seconds := int(duration.Seconds()) % 60

		neighbour := trafficStat{
			Since:    fr.Since.Format("2006-01-02 15:04:05"),
			Host:     fr.Hostname,
			IP:       fr.OrigIP,
			TempIP:   firewall.IP4fromOffset(fr.DestIPOffset),
			Bytes:    fr.BytesUsed,
			Duration: fmt.Sprintf("%d:%02d:%02d", hours, minutes, seconds),
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
