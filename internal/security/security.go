package security

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sleuth/internal/db"
	"strconv"
	"strings"
	"time"
)

type Security struct {
	db *db.Db
}

func InitSession(db *db.Db) *Security {
	return &Security{db: db}
}

func (s *Security) GetSession(IP string) (string, error) {
	ses := s.db.GetSession(IP)
	if ses != nil {
		return ses.Username, nil
	}
	return "", fmt.Errorf("session does not exist")
}

func (s *Security) ClearSession(IP string) error {
	return s.db.DeleteSession(IP)
}

func (s *Security) CreateSession(IP string, Username string) {
	s.db.CreateSession(&db.Session{
		IP:       IP,
		Username: Username,
	})
}

func (s *Security) IsAllowedAccess(IP string) bool {
	sess := s.db.GetSessions()
	fmt.Print(sess)
	if session := s.db.GetSession(IP); session != nil {
		if user := s.db.GetUser(session.Username); user != nil && user.Enabled {
			return true
		}
	}
	return false
}

func (s *Security) IsAllowedPortalAccess(Username string) bool {
	user := s.db.GetUser(Username)
	if user != nil {
		if user.Enabled {
			role := s.db.GetRole(user.Role)
			if role != nil {
				return role.Admin
			}
		}
	}
	return false
}

func isValidHostSourceRecord(split []string) bool {
	if len(split) == 0 {
		return false
	}
	if len(split) > 2 {
		return false
	}
	if len(split) == 2 {
		if split[0] != "0.0.0.0" {
			return false
		}
		if split[0] == "0.0.0.0" && split[1] == "0.0.0.0" {
			return false
		}
	}
	return true
}

func (s Security) UpdateRuleSet(rs db.DNSRuleSet) error {
	if !rs.Enabled {
		return fmt.Errorf("Ruleset %s not enabled", rs.RuleSetName)
	}
	if rs.Source == "" {
		return fmt.Errorf("Ruleset %s source not specified", rs.RuleSetName)
	}

	data, err := getUrlData(rs.Source)
	if err != nil {
		return fmt.Errorf("Unable to fetch ruleset %s: %w", rs.RuleSetName, err)
	}

	var list = make([]string, 0)
	reader := bytes.NewReader(data)
	fileScanner := bufio.NewScanner(reader)
	fileScanner.Split(bufio.ScanLines)
	re := regexp.MustCompile(`\s+`)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if line != "" && line[0] != '#' {
			split := re.Split(line, -1)
			if isValidHostSourceRecord(split) {
				if len(split) == 2 {
					list = append(list, strings.ToLower(split[1])+".")
				} else if len(split) == 1 {
					list = append(list, strings.ToLower(split[0])+".")
				}
			}
		}
	}
	rs.Rules = list
	rs.LastUpdated = time.Now()
	return s.db.UpdateDNSRuleSet(&rs)

}

func getUrlData(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("received invalid http response code " + strconv.Itoa(resp.StatusCode) + "for url " + url)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
