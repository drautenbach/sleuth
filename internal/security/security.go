package security

import (
	"fmt"
	"sleuth/internal/db"
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
