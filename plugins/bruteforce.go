package plugins

import (
	"DORM/models"
	"fmt"
	"time"

	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

// 73. (SSH & FTP BRUTE FORCE)
type BruteForcePlugin struct{}

func (p *BruteForcePlugin) Name() string { return "Mini-Hydra (SSH/FTP Brute Force)" }

func (p *BruteForcePlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if target.Port != 22 && target.Port != 21 {
		return nil
	}

	creds := []struct{ User, Pass string }{
		{"root", "root"},
		{"admin", "admin"},
		{"root", "toor"},
		{"user", "user"},
		{"admin", "password"},
		{"root", "123456"},
		{"administrator", "password"},
		{"ubuntu", "ubuntu"},
		{"pi", "raspberry"},
		{"vagrant", "vagrant"},
	}

	foundCreds := ""

	if target.Port == 21 {
		for _, c := range creds {
			conn, err := ftp.Dial(fmt.Sprintf("%s:%d", target.IP, target.Port), ftp.DialWithTimeout(2*time.Second))
			if err == nil {
				err = conn.Login(c.User, c.Pass)
				if err == nil {

					foundCreds = fmt.Sprintf("FTP Cracked! User: '%s' Pass: '%s'", c.User, c.Pass)
					conn.Logout()
					conn.Quit()
					break
				}
				conn.Quit()
			}

		}
	}

	if target.Port == 22 {
		for _, c := range creds {
			config := &ssh.ClientConfig{
				User: c.User,
				Auth: []ssh.AuthMethod{
					ssh.Password(c.Pass),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.IP, target.Port), config)
			if err == nil {

				foundCreds = fmt.Sprintf("SSH Cracked! User: '%s' Pass: '%s'", c.User, c.Pass)
				client.Close()
				break
			}
		}
	}

	if foundCreds != "" {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Critical Access: Default Password (Brute-Force)",
			Severity:    "CRITICAL",
			CVSS:        10.0,
			Description: "Logged in with default/weak password: " + foundCreds,
			Solution:    "Change all default passwords immediately and use SSH key-based auth.",
			Reference:   "CWE-521: Weak Password Requirements",
		}
	}

	return nil
}
