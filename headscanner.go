package main

// ==========================================
// DORM DEEP FINGERPRINTING ENGINE
// ==========================================

import (
	"crypto/tls"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TechNode represents a parsed technology and its exact version
type TechNode struct {
	Product string
	Version string
}

type TechProfile struct {
	Techs []TechNode
	WAF   string
	CMS   string
}

var scanCache sync.Map

func DeepScanTarget(targetURL string) *TechProfile {

	if cached, ok := scanCache.Load(targetURL); ok {
		return cached.(*TechProfile)
	}

	profile := &TechProfile{}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return profile
	}
	req.Header.Set("User-Agent", "DORM-Enterprise-Scanner/1.5.0")

	resp, err := client.Do(req)
	if err != nil {
		return profile
	}
	defer resp.Body.Close()

	re := regexp.MustCompile(`(?i)([a-zA-Z0-9\-]+)(?:/|\s+v?)([0-9]+(?:\.[0-9]+)*)`)
	headersToScan := []string{"Server", "X-Powered-By", "X-Generator"}

	for _, h := range headersToScan {
		val := resp.Header.Get(h)
		if val == "" {
			continue
		}

		matches := re.FindAllStringSubmatch(val, -1)
		for _, m := range matches {
			if len(m) >= 3 {
				prodName := strings.ToLower(m[1])
				// ALIAS ENGINE: "microsoft-iis" -> "iis"
				if prodName == "microsoft-iis" {
					prodName = "iis"
				}
				profile.Techs = append(profile.Techs, TechNode{
					Product: prodName,
					Version: m[2],
				})
			}
		}

		if h == "X-Generator" && len(matches) == 0 {
			profile.Techs = append(profile.Techs, TechNode{
				Product: strings.ToLower(strings.Split(val, " ")[0]),
				Version: "",
			})
		}
	}

	// 2. COOKIE FREAMEWORK DETECTION
	for _, cookie := range resp.Cookies() {
		cookieName := strings.ToUpper(cookie.Name)
		if strings.Contains(cookieName, "JSESSIONID") {
			profile.Techs = append(profile.Techs, TechNode{Product: "java", Version: ""})
		} else if strings.Contains(cookieName, "PHPSESSID") {
			profile.Techs = append(profile.Techs, TechNode{Product: "php", Version: ""})
		} else if strings.Contains(cookieName, "ASPSESSIONID") || strings.Contains(cookieName, "ASP.NET_SESSIONID") {
			profile.Techs = append(profile.Techs, TechNode{Product: "asp.net", Version: ""})
		}
	}

	// 3. WAF & CDN FINGERPRINTING
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	viaHeader := strings.ToLower(resp.Header.Get("Via"))

	if strings.Contains(serverHeader, "cloudflare") || resp.Header.Get("CF-RAY") != "" {
		profile.WAF = "Cloudflare"
	} else if strings.Contains(serverHeader, "f5") {
		profile.WAF = "F5 BIG-IP"
	} else if strings.Contains(serverHeader, "akamai") {
		profile.WAF = "Akamai"
	} else if strings.Contains(viaHeader, "cloudfront") {
		profile.WAF = "AWS CloudFront"
	}

	scanCache.Store(targetURL, profile)

	return profile
}
