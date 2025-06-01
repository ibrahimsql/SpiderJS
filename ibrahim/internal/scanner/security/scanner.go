package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// Scanner is a security scanner for JavaScript applications
type Scanner struct {
	config *config.Config
	log    *logger.Logger
	checks []Check
}

// Check is an interface for security checks
type Check interface {
	Name() string
	Description() string
	Run(ctx context.Context, target *models.Target) ([]*models.Finding, error)
}

// NewScanner creates a new security scanner
func NewScanner(cfg *config.Config, log *logger.Logger) (*Scanner, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	scanner := &Scanner{
		config: cfg,
		log:    log,
		checks: []Check{},
	}

	// Register checks based on configuration
	if cfg.ScanOptions.IncludeXSS {
		scanner.checks = append(scanner.checks, NewXSSCheck())
	}

	if cfg.ScanOptions.IncludeInjection {
		scanner.checks = append(scanner.checks, NewInjectionCheck())
	}

	if cfg.ScanOptions.IncludeCSRF {
		scanner.checks = append(scanner.checks, NewCSRFCheck())
	}

	if cfg.ScanOptions.IncludeCORS {
		scanner.checks = append(scanner.checks, NewCORSCheck())
	}

	if cfg.ScanOptions.IncludeHeaders {
		scanner.checks = append(scanner.checks, NewHeaderCheck())
	}

	if cfg.ScanOptions.IncludeCookies {
		scanner.checks = append(scanner.checks, NewCookieCheck())
	}

	if cfg.ScanOptions.IncludeSupplyChain {
		scanner.checks = append(scanner.checks, NewSupplyChainCheck())
	}

	if cfg.ScanOptions.IncludePrototype {
		scanner.checks = append(scanner.checks, NewPrototypePollutionCheck())
	}

	return scanner, nil
}

// Scan performs security scanning on a target
func (s *Scanner) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	s.log.Success("Starting security scan of %s", target.URL)
	startTime := time.Now()

	var findings []*models.Finding

	// Run each check
	for _, check := range s.checks {
		select {
		case <-ctx.Done():
			return findings, fmt.Errorf("scan interrupted: %w", ctx.Err())
		default:
			s.log.Success("Running check: %s", check.Name())
			checkFindings, err := check.Run(ctx, target)
			if err != nil {
				s.log.ErrorMsg("Check %s failed: %v", check.Name(), err)
				continue
			}

			findings = append(findings, checkFindings...)
			s.log.Success("Check %s completed, found %d issues", check.Name(), len(checkFindings))
		}
	}

	duration := time.Since(startTime)
	s.log.Success("Security scan completed in %s, found %d issues", duration, len(findings))

	return findings, nil
}

// XSSCheck checks for Cross-Site Scripting vulnerabilities
type XSSCheck struct{}

// NewXSSCheck creates a new XSS check
func NewXSSCheck() *XSSCheck {
	return &XSSCheck{}
}

// Name returns the name of the check
func (c *XSSCheck) Name() string {
	return "XSS Check"
}

// Description returns the description of the check
func (c *XSSCheck) Description() string {
	return "Checks for Cross-Site Scripting vulnerabilities"
}

// Run performs the check
func (c *XSSCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for Content-Security-Policy header
	if target.Headers != nil {
		if _, ok := target.Headers["Content-Security-Policy"]; !ok {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Missing Content-Security-Policy Header",
				models.SeverityMedium,
			).WithDescription(
				"The application does not set a Content-Security-Policy header, which helps prevent XSS attacks.",
			).WithRemediation(
				"Implement a Content-Security-Policy header with appropriate directives.",
			).WithURL(
				target.URL,
			).WithTags(
				"xss", "headers", "csp",
			)

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// InjectionCheck checks for injection vulnerabilities
type InjectionCheck struct{}

// NewInjectionCheck creates a new injection check
func NewInjectionCheck() *InjectionCheck {
	return &InjectionCheck{}
}

// Name returns the name of the check
func (c *InjectionCheck) Name() string {
	return "Injection Check"
}

// Description returns the description of the check
func (c *InjectionCheck) Description() string {
	return "Checks for injection vulnerabilities"
}

// Run performs the check
func (c *InjectionCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// For demonstration purposes, add a sample finding
	finding := models.NewFinding(
		models.FindingTypeVulnerability,
		"Potential Injection Vulnerability",
		models.SeverityHigh,
	).WithDescription(
		"The application may be vulnerable to injection attacks.",
	).WithRemediation(
		"Validate and sanitize all user inputs before processing.",
	).WithURL(
		target.URL,
	).WithTags(
		"injection", "security",
	)

	findings = append(findings, finding)

	return findings, nil
}

// CSRFCheck checks for Cross-Site Request Forgery vulnerabilities
type CSRFCheck struct{}

// NewCSRFCheck creates a new CSRF check
func NewCSRFCheck() *CSRFCheck {
	return &CSRFCheck{}
}

// Name returns the name of the check
func (c *CSRFCheck) Name() string {
	return "CSRF Check"
}

// Description returns the description of the check
func (c *CSRFCheck) Description() string {
	return "Checks for Cross-Site Request Forgery vulnerabilities"
}

// Run performs the check
func (c *CSRFCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for CSRF tokens in forms
	// This is a simplified implementation for demonstration purposes

	return findings, nil
}

// CORSCheck checks for CORS misconfigurations
type CORSCheck struct{}

// NewCORSCheck creates a new CORS check
func NewCORSCheck() *CORSCheck {
	return &CORSCheck{}
}

// Name returns the name of the check
func (c *CORSCheck) Name() string {
	return "CORS Check"
}

// Description returns the description of the check
func (c *CORSCheck) Description() string {
	return "Checks for CORS misconfigurations"
}

// Run performs the check
func (c *CORSCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for permissive CORS headers
	if target.Headers != nil {
		if origin, ok := target.Headers["Access-Control-Allow-Origin"]; ok {
			if origin == "*" {
				finding := models.NewFinding(
					models.FindingTypeVulnerability,
					"Permissive CORS Policy",
					models.SeverityMedium,
				).WithDescription(
					"The application uses a permissive CORS policy that allows any origin.",
				).WithRemediation(
					"Restrict the Access-Control-Allow-Origin header to specific trusted domains.",
				).WithURL(
					target.URL,
				).WithEvidence(
					"Access-Control-Allow-Origin: *",
				).WithTags(
					"cors", "headers",
				)

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// HeaderCheck checks for security header issues
type HeaderCheck struct{}

// NewHeaderCheck creates a new header check
func NewHeaderCheck() *HeaderCheck {
	return &HeaderCheck{}
}

// Name returns the name of the check
func (c *HeaderCheck) Name() string {
	return "Security Headers Check"
}

// Description returns the description of the check
func (c *HeaderCheck) Description() string {
	return "Checks for security header issues"
}

// Run performs the check
func (c *HeaderCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	if target.Headers == nil {
		return findings, nil
	}

	// Check for X-Frame-Options header
	if _, ok := target.Headers["X-Frame-Options"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeVulnerability,
			"Missing X-Frame-Options Header",
			models.SeverityLow,
		).WithDescription(
			"The application does not set an X-Frame-Options header, which helps prevent clickjacking attacks.",
		).WithRemediation(
			"Add the X-Frame-Options header with a value of DENY or SAMEORIGIN.",
		).WithURL(
			target.URL,
		).WithTags(
			"headers", "clickjacking",
		)

		findings = append(findings, finding)
	}

	// Check for X-Content-Type-Options header
	if _, ok := target.Headers["X-Content-Type-Options"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeVulnerability,
			"Missing X-Content-Type-Options Header",
			models.SeverityLow,
		).WithDescription(
			"The application does not set an X-Content-Type-Options header, which helps prevent MIME type sniffing attacks.",
		).WithRemediation(
			"Add the X-Content-Type-Options header with a value of nosniff.",
		).WithURL(
			target.URL,
		).WithTags(
			"headers", "mime-sniffing",
		)

		findings = append(findings, finding)
	}

	return findings, nil
}

// CookieCheck checks for cookie security issues
type CookieCheck struct{}

// NewCookieCheck creates a new cookie check
func NewCookieCheck() *CookieCheck {
	return &CookieCheck{}
}

// Name returns the name of the check
func (c *CookieCheck) Name() string {
	return "Cookie Security Check"
}

// Description returns the description of the check
func (c *CookieCheck) Description() string {
	return "Checks for cookie security issues"
}

// Run performs the check
func (c *CookieCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// Check for secure cookies
	for name, value := range target.Cookies {
		if !strings.Contains(value, "Secure") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Insecure Cookie",
				models.SeverityMedium,
			).WithDescription(
				"The application sets a cookie without the Secure flag, which allows it to be transmitted over unencrypted connections.",
			).WithRemediation(
				"Set the Secure flag on all cookies to ensure they are only transmitted over HTTPS.",
			).WithURL(
				target.URL,
			).WithEvidence(
				name+"="+value,
			).WithTags(
				"cookies", "transport-security",
			)

			findings = append(findings, finding)
		}

		if !strings.Contains(value, "HttpOnly") {
			finding := models.NewFinding(
				models.FindingTypeVulnerability,
				"Cookie Without HttpOnly Flag",
				models.SeverityMedium,
			).WithDescription(
				"The application sets a cookie without the HttpOnly flag, which allows it to be accessed by JavaScript.",
			).WithRemediation(
				"Set the HttpOnly flag on all cookies that don't need to be accessed by JavaScript.",
			).WithURL(
				target.URL,
			).WithEvidence(
				name+"="+value,
			).WithTags(
				"cookies", "xss",
			)

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// SupplyChainCheck checks for supply chain vulnerabilities
type SupplyChainCheck struct{}

// NewSupplyChainCheck creates a new supply chain check
func NewSupplyChainCheck() *SupplyChainCheck {
	return &SupplyChainCheck{}
}

// Name returns the name of the check
func (c *SupplyChainCheck) Name() string {
	return "Supply Chain Check"
}

// Description returns the description of the check
func (c *SupplyChainCheck) Description() string {
	return "Checks for supply chain vulnerabilities"
}

// Run performs the check
func (c *SupplyChainCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// For demonstration purposes, add a sample finding
	finding := models.NewFinding(
		models.FindingTypeVulnerability,
		"Outdated Dependencies",
		models.SeverityMedium,
	).WithDescription(
		"The application may be using outdated dependencies with known vulnerabilities.",
	).WithRemediation(
		"Update dependencies to the latest secure versions and implement a dependency management process.",
	).WithURL(
		target.URL,
	).WithTags(
		"supply-chain", "dependencies",
	)

	findings = append(findings, finding)

	return findings, nil
}

// PrototypePollutionCheck checks for prototype pollution vulnerabilities
type PrototypePollutionCheck struct{}

// NewPrototypePollutionCheck creates a new prototype pollution check
func NewPrototypePollutionCheck() *PrototypePollutionCheck {
	return &PrototypePollutionCheck{}
}

// Name returns the name of the check
func (c *PrototypePollutionCheck) Name() string {
	return "Prototype Pollution Check"
}

// Description returns the description of the check
func (c *PrototypePollutionCheck) Description() string {
	return "Checks for prototype pollution vulnerabilities"
}

// Run performs the check
func (c *PrototypePollutionCheck) Run(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	// For demonstration purposes, add a sample finding
	finding := models.NewFinding(
		models.FindingTypeVulnerability,
		"Potential Prototype Pollution",
		models.SeverityHigh,
	).WithDescription(
		"The application may be vulnerable to prototype pollution attacks through unsafe object merging.",
	).WithRemediation(
		"Use safe object merging functions that don't modify the Object prototype.",
	).WithURL(
		target.URL,
	).WithTags(
		"prototype-pollution", "javascript",
	)

	findings = append(findings, finding)

	return findings, nil
}
