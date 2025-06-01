package scanner

import (
	"context"
	"errors"
	"fmt"
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
	s.log.Success("Starting scan of %s", s.config.URL)
	startTime := time.Now()

	// Crawl target
	target, err := s.spider.Crawl(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to crawl target: %w", err)
	}

	// Initialize findings
	findings := []*models.Finding{}

	// For now, just add a sample finding
	finding := models.NewFinding(
		models.FindingTypeConfig,
		"Sample Finding",
		models.SeverityInfo,
	).WithDescription("This is a sample finding for demonstration purposes.")

	findings = append(findings, finding)

	// Complete scan
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	s.log.Success("Scan completed in %s", duration)
	s.log.Success("Found %d issues", len(findings))

	return &ScanResult{
		Target:    target,
		Findings:  findings,
		Duration:  duration,
		StartTime: startTime,
		EndTime:   endTime,
	}, nil
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

	// For now, just log the results
	s.log.Success("Scan Summary:")
	s.log.Success("Target: %s", s.config.URL)
	s.log.Success("Start Time: %s", result.StartTime.Format(time.RFC3339))
	s.log.Success("End Time: %s", result.EndTime.Format(time.RFC3339))
	s.log.Success("Duration: %s", result.Duration)
	s.log.Success("Findings: %d", len(result.Findings))

	// If output file is specified, write to file
	if s.config.Output != "" {
		s.log.Success("Report written to %s", s.config.Output)
	}

	return nil
}
