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

func (s *Security) CreateSession(IP string, Username string) {
	s.db.CreateSession(&db.Session{
		IP:       IP,
		Username: Username,
	})
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
