package plugins

import (
	"DORM/models"
	"context"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// 71. DOM XSS & SPA SCANNER (HEADLESS CHROME)
type DOMScannerPlugin struct{}

func (p *DOMScannerPlugin) Name() string { return "DOM XSS & SPA Scanner (Chrome)" }

func (p *DOMScannerPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	payload := "dorm_xss_check"
	targetURL := getURL(target, "/#"+payload)

	var res string

	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),

		chromedp.WaitVisible("body", chromedp.ByQuery),

		chromedp.OuterHTML("html", &res),
	)

	if err != nil {

		return nil
	}

	if strings.Contains(res, payload) {
		return &models.Vulnerability{
			Target:      target,
			Name:        "DOM Based XSS / Reflected",
			Severity:    "HIGH",
			CVSS:        7.2,
			Description: "Payload detected in DOM after JavaScript rendering (SPA models.Vulnerability).",
			Solution:    "Sanitize user inputs in JavaScript.",
			Reference:   "OWASP DOM XSS",
		}
	}
	return nil
}
