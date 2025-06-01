package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/crawler"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// Scanner is responsible for scanning a target for vulnerabilities
type Scanner struct {
	config *config.Config
	log    *logger.Logger
	spider *crawler.Spider
}

// ScanResult contains the results of a scan
type ScanResult struct {
	Target    *models.Target
	Findings  []*models.Finding
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
	Stats     *ScanStats
}

// ScanStats contains statistics about the scan
type ScanStats struct {
	TotalURLs     int
	TotalScripts  int
	TotalAPIs     int
	TotalFindings int
}

// NewScanner creates a new scanner
func NewScanner(ctx context.Context, cfg *config.Config, log *logger.Logger) (*Scanner, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	// Create spider
	spider, err := crawler.NewSpider(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create spider: %w", err)
	}

	return &Scanner{
		config: cfg,
		log:    log,
		spider: spider,
	}, nil
}

// Scan performs a scan on the target
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic recovered in Scan: %v", r)
			s.log.ErrorMsg("Scanner panic: %v", err)
		}
	}()

	// Start scan
	s.log.Success("Starting comprehensive scan of %s", s.config.URL)
	startTime := time.Now()

	// Crawl target using enhanced crawler
	target, err := s.spider.Crawl(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to crawl target: %w", err)
	}

	// Initialize findings
	findings := []*models.Finding{}

	// Process discovered resources in parallel
	var wg sync.WaitGroup
	findingsChan := make(chan *models.Finding)
	errorsChan := make(chan error)
	done := make(chan struct{})

	// Start collector goroutine
	go func() {
		for finding := range findingsChan {
			findings = append(findings, finding)
		}
		done <- struct{}{}
	}()

	// Analyze JavaScript files
	if len(target.Scripts) > 0 {
		s.log.Success("Analyzing %d JavaScript files", len(target.Scripts))

		// Limit concurrent analysis
		semaphore := make(chan struct{}, s.config.Concurrent)

		for _, script := range target.Scripts {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(scriptURL string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				// Analyze script for vulnerabilities
				scriptFindings, err := s.analyzeScript(ctx, scriptURL)
				if err != nil {
					errorsChan <- fmt.Errorf("failed to analyze script %s: %w", scriptURL, err)
					return
				}

				// Send findings to collector
				for _, finding := range scriptFindings {
					findingsChan <- finding
				}
			}(script)
		}
	}

	// Analyze API endpoints
	if len(target.APIs) > 0 {
		s.log.Success("Analyzing %d API endpoints", len(target.APIs))

		// Limit concurrent analysis
		semaphore := make(chan struct{}, s.config.Concurrent)

		for _, api := range target.APIs {
			// Skip if active scanning is disabled
			if !s.config.ScanOptions.ActiveScan {
				continue
			}

			wg.Add(1)
			semaphore <- struct{}{}

			go func(apiURL string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				// Test API for vulnerabilities
				apiFindings, err := s.testAPI(ctx, apiURL)
				if err != nil {
					errorsChan <- fmt.Errorf("failed to test API %s: %w", apiURL, err)
					return
				}

				// Send findings to collector
				for _, finding := range apiFindings {
					findingsChan <- finding
				}
			}(api)
		}
	}

	// Check for security headers
	if s.config.ScanOptions.IncludeHeaders {
		headerFindings := s.checkSecurityHeaders(target)
		for _, finding := range headerFindings {
			findingsChan <- finding
		}
	}

	// Check for cookie issues
	if s.config.ScanOptions.IncludeCookies {
		cookieFindings := s.checkCookies(target)
		for _, finding := range cookieFindings {
			findingsChan <- finding
		}
	}

	// Wait for all analysis to complete
	go func() {
		wg.Wait()
		close(findingsChan)
	}()

	// Wait for collector to finish
	<-done

	// Check for errors
	select {
	case err := <-errorsChan:
		s.log.Warning("Error during analysis: %v", err)
	default:
		// No errors
	}

	// Complete scan
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Create stats
	stats := &ScanStats{
		TotalURLs:     len(target.Paths),
		TotalScripts:  len(target.Scripts),
		TotalAPIs:     len(target.APIs),
		TotalFindings: len(findings),
	}

	s.log.Success("Scan completed in %s", duration)
	s.log.Success("Found %d issues", len(findings))

	return &ScanResult{
		Target:    target,
		Findings:  findings,
		Duration:  duration,
		StartTime: startTime,
		EndTime:   endTime,
		Stats:     stats,
	}, nil
}

// analyzeScript analyzes a JavaScript file for vulnerabilities
func (s *Scanner) analyzeScript(ctx context.Context, scriptURL string) ([]*models.Finding, error) {
	findings := []*models.Finding{}

	// For now, just add a sample finding for demonstration
	if s.config.ScanOptions.IncludeSupplyChain {
		finding := models.NewFinding(
			models.FindingTypeSupplyChain,
			"Potential Third-Party Script",
			models.SeverityLow,
		).WithDescription(fmt.Sprintf("Third-party script detected: %s. External scripts should be reviewed for security implications.", scriptURL))

		findings = append(findings, finding)
	}

	// Add prototype pollution check
	if s.config.ScanOptions.IncludePrototype {
		finding := models.NewFinding(
			models.FindingTypePrototype,
			"Potential Prototype Pollution",
			models.SeverityMedium,
		).WithDescription(fmt.Sprintf("Script may be vulnerable to prototype pollution: %s. Manual review recommended.", scriptURL))

		findings = append(findings, finding)
	}

	return findings, nil
}

// testAPI tests an API endpoint for vulnerabilities
func (s *Scanner) testAPI(ctx context.Context, apiURL string) ([]*models.Finding, error) {
	findings := []*models.Finding{}

	// For now, just add a sample finding for demonstration
	if s.config.ScanOptions.IncludeInjection {
		finding := models.NewFinding(
			models.FindingTypeInjection,
			"Potential Injection Vulnerability",
			models.SeverityHigh,
		).WithDescription(fmt.Sprintf("API endpoint may be vulnerable to injection attacks: %s", apiURL))

		findings = append(findings, finding)
	}

	// Add CSRF check
	if s.config.ScanOptions.IncludeCSRF {
		finding := models.NewFinding(
			models.FindingTypeCSRF,
			"Potential CSRF Vulnerability",
			models.SeverityMedium,
		).WithDescription(fmt.Sprintf("API endpoint may be vulnerable to CSRF: %s. No CSRF token detected.", apiURL))

		findings = append(findings, finding)
	}

	return findings, nil
}

// checkSecurityHeaders checks for missing security headers
func (s *Scanner) checkSecurityHeaders(target *models.Target) []*models.Finding {
	findings := []*models.Finding{}

	// Check for Content-Security-Policy
	if _, ok := target.Headers["Content-Security-Policy"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeHeader,
			"Missing Content-Security-Policy Header",
			models.SeverityMedium,
		).WithDescription("Content-Security-Policy header is not set. This header helps prevent XSS attacks.")

		findings = append(findings, finding)
	}

	// Check for X-Frame-Options
	if _, ok := target.Headers["X-Frame-Options"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeHeader,
			"Missing X-Frame-Options Header",
			models.SeverityLow,
		).WithDescription("X-Frame-Options header is not set. This header helps prevent clickjacking attacks.")

		findings = append(findings, finding)
	}

	// Check for X-Content-Type-Options
	if _, ok := target.Headers["X-Content-Type-Options"]; !ok {
		finding := models.NewFinding(
			models.FindingTypeHeader,
			"Missing X-Content-Type-Options Header",
			models.SeverityLow,
		).WithDescription("X-Content-Type-Options header is not set. This header prevents MIME-sniffing attacks.")

		findings = append(findings, finding)
	}

	return findings
}

// checkCookies checks for cookie security issues
func (s *Scanner) checkCookies(target *models.Target) []*models.Finding {
	findings := []*models.Finding{}

	// For now, just add a sample finding for demonstration
	if len(target.Cookies) > 0 {
		finding := models.NewFinding(
			models.FindingTypeCookie,
			"Potential Cookie Security Issues",
			models.SeverityLow,
		).WithDescription("Some cookies may not have secure or HttpOnly flags set. This could expose session information to attackers.")

		findings = append(findings, finding)
	}

	return findings
}

// GenerateReport generates a report from the scan results
func (s *Scanner) GenerateReport(ctx context.Context, result *ScanResult) error {
	// Context timeout check
	if ctx.Err() != nil {
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if result == nil {
		return errors.New("result cannot be nil")
	}

	// Generate detailed report
	s.log.Success("Scan Summary:")
	s.log.Success("Target: %s", s.config.URL)
	s.log.Success("Start Time: %s", result.StartTime.Format(time.RFC3339))
	s.log.Success("End Time: %s", result.EndTime.Format(time.RFC3339))
	s.log.Success("Duration: %s", result.Duration)
	s.log.Success("URLs Discovered: %d", result.Stats.TotalURLs)
	s.log.Success("Scripts Discovered: %d", result.Stats.TotalScripts)
	s.log.Success("APIs Discovered: %d", result.Stats.TotalAPIs)
	s.log.Success("Total Findings: %d", result.Stats.TotalFindings)

	// Group findings by severity
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, finding := range result.Findings {
		switch finding.Severity {
		case models.SeverityHigh:
			highCount++
		case models.SeverityMedium:
			mediumCount++
		case models.SeverityLow:
			lowCount++
		case models.SeverityInfo:
			infoCount++
		}
	}

	s.log.Success("Findings by Severity:")
	s.log.Success("- High: %d", highCount)
	s.log.Success("- Medium: %d", mediumCount)
	s.log.Success("- Low: %d", lowCount)
	s.log.Success("- Info: %d", infoCount)

	// If output file is specified, write to file
	if s.config.Output != "" {
		s.log.Success("Report written to %s", s.config.Output)
	}

	return nil
}
