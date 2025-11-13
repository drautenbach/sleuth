package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type wcSystem struct {
}

type shadowUser struct {
	Password   string
	ExpireDate int64 // days since Unix epoch
}

type LocalUser struct {
	Username  string
	UID       string
	SuperUser bool
}

func wcSystemInit(p *Portal) *wcSystem {
	s := &wcSystem{}
	p.server.router.GET("/system/users", func(c *gin.Context) {

		LocalUsers, LocalUsersError := s.GetLocalUsers()
		p.server.HTML(c, "system_users", gin.H{
			"model": gin.H{
				"LocalUsers":      LocalUsers,
				"LocalUsersError": LocalUsersError,
			},
		})
	})

	p.server.router.GET("/system/network", func(c *gin.Context) {
		p.server.HTML(c, "system_network", gin.H{
			"model": gin.H{
				"adapters": p.network.Adapters,
			},
		})
	})
	return s
}

func (wcSystem) GetLocalUsers() ([]LocalUser, error) {
	passwd, error := os.Open("/etc/passwd")
	if error != nil {
		return []LocalUser{}, error
	}
	defer passwd.Close()

	shadowFile, error := os.Open("/etc/shadow")
	var shadowUsers = make(map[string]shadowUser)
	if error == nil {
		shadowScanner := bufio.NewScanner(shadowFile)
		for shadowScanner.Scan() {
			shadowfields := strings.Split(shadowScanner.Text(), ":")
			if len(shadowfields) >= 9 {
				username := shadowfields[0]
				if userStatus, exists := shadowUsers[username]; !exists {
					userStatus.Password = shadowfields[1]
					// Eighth field (index 7) is account expiration date (days since epoch)
					if shadowfields[7] != "" && shadowfields[7] != "-1" {
						if expiryDays, err := strconv.ParseInt(shadowfields[7], 10, 64); err == nil {
							userStatus.ExpireDate = expiryDays
						}
					}
					shadowUsers[username] = userStatus
				}
			}
		}

	}
	defer shadowFile.Close()

	var users []LocalUser

	scanner := bufio.NewScanner(passwd)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")

		if len(parts) >= 6 {
			if parts[5] != "/sbin/nologin" && parts[5] != "/bin/false" && parts[5] != "" {
				var include = true
				if error == nil {
					u := shadowUsers[parts[0]]
					if u.ExpireDate != 0 {
						expireTime := u.ExpireDate * 86400 // convert days to seconds
						if expireTime < (time.Now().Unix()) {
							include = false
						}
					}
					if u.Password == "" || u.Password[0] == '*' || u.Password[0] == '!' {
						include = false
					}
				}
				if include {

					cmd := exec.Command("sudo", "-lU", parts[0])
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					su := false
					if error == nil {
						err := cmd.Run()
						su = err == nil || (!strings.Contains(stderr.String(), "not allowed to run sudo") && !strings.Contains(stderr.String(), "unknown user"))
					}

					users = append(users, LocalUser{
						Username:  parts[0],
						UID:       parts[2],
						SuperUser: su,
					})
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return []LocalUser{}, err
	}
	return users, error
}
