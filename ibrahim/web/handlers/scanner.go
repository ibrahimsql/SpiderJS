package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/analyzer"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// Scanner is responsible for scanning websites and analyzing JavaScript
type Scanner struct {
	log      *logger.Logger
	config   *config.Config
	analyzer *analyzer.BundleAnalyzer
	client   *http.Client
	jobs     map[string]*ScanJob
	mu       sync.RWMutex
}

// ScanJob represents an active scanning job
type ScanJob struct {
	ID         string
	URL        string
	StartTime  time.Time
	Status     string
	Progress   int
	Result     *models.ScanResult
	Error      error
	cancelFunc context.CancelFunc
}

// ScanRequest represents a request to scan a website
type ScanRequest struct {
	URL     string `json:"url"`
	Timeout int    `json:"timeout,omitempty"`
	Depth   int    `json:"depth,omitempty"`
}

// ScanResponse represents the response from a scan request
type ScanResponse struct {
	JobID     string    `json:"job_id"`
	URL       string    `json:"url"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"start_time"`
}

// NewScanner creates a new website scanner
func NewScanner(log *logger.Logger, config *config.Config, analyzer *analyzer.BundleAnalyzer) *Scanner {
	return &Scanner{
		log:      log,
		config:   config,
		analyzer: analyzer,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		jobs: make(map[string]*ScanJob),
	}
}

// Scan starts a new scan job for the given URL
func (s *Scanner) Scan(ctx context.Context, urlStr string) (*ScanResponse, error) {
	// Validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Ensure URL has scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		urlStr = parsedURL.String()
	}

	// Create job ID
	jobID := fmt.Sprintf("scan_%d", time.Now().UnixNano())

	// Create cancel context
	jobCtx, cancelFunc := context.WithCancel(ctx)

	// Create job
	job := &ScanJob{
		ID:         jobID,
		URL:        urlStr,
		StartTime:  time.Now(),
		Status:     "running",
		Progress:   0,
		cancelFunc: cancelFunc,
	}

	// Store job
	s.mu.Lock()
	s.jobs[jobID] = job
	s.mu.Unlock()

	// Start scan in background
	go s.runScan(jobCtx, job)

	// Return response
	return &ScanResponse{
		JobID:     jobID,
		URL:       urlStr,
		Status:    job.Status,
		StartTime: job.StartTime,
	}, nil
}

// GetJob returns the job with the given ID
func (s *Scanner) GetJob(jobID string) (*ScanJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.jobs[jobID]
	return job, ok
}

// CancelJob cancels the job with the given ID
func (s *Scanner) CancelJob(jobID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.jobs[jobID]
	if !ok {
		return false
	}

	job.Status = "cancelled"
	job.cancelFunc()
	return true
}

// runScan performs the actual website scan
func (s *Scanner) runScan(ctx context.Context, job *ScanJob) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("Scan job panicked", "job_id", job.ID, "panic", r)

			s.mu.Lock()
			job.Status = "failed"
			job.Error = fmt.Errorf("internal error: %v", r)
			s.mu.Unlock()
		}
	}()

	s.log.Info("Starting scan job", "job_id", job.ID, "url", job.URL)

	// Create target
	_, err := models.NewTarget(job.URL)
	if err != nil {
		s.log.Error("Failed to create target", "job_id", job.ID, "error", err)

		s.mu.Lock()
		job.Status = "failed"
		job.Error = err
		s.mu.Unlock()
		return
	}

	// TODO: Implement actual crawling and script extraction
	// For now, we'll just simulate progress updates

	for i := 0; i <= 100; i += 10 {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			s.log.Info("Scan job cancelled", "job_id", job.ID)
			return
		default:
			// Continue
		}

		// Update progress
		s.mu.Lock()
		job.Progress = i
		s.mu.Unlock()

		// Simulate work
		time.Sleep(500 * time.Millisecond)
	}

	// Simulate analysis result
	result := &models.ScanResult{
		URL:             job.URL,
		ScannedAt:       job.StartTime,
		CompletedAt:     time.Now(),
		ScriptsFound:    5,
		ScriptsAnalyzed: 5,
		BundleTypes: map[string]int{
			"webpack": 2,
			"rollup":  1,
			"unknown": 2,
		},
		Dependencies: []*models.Dependency{
			{Name: "react", Version: "16.13.1"},
			{Name: "react-dom", Version: "16.13.1"},
			{Name: "lodash", Version: "4.17.15"},
			{Name: "axios", Version: "0.19.2"},
		},
		Vulnerabilities: []*models.Vulnerability{
			{
				Type:        "eval",
				Severity:    "high",
				Description: "Direct eval usage found",
				Location:    "script3.js:42",
			},
			{
				Type:        "innerHTML",
				Severity:    "medium",
				Description: "Direct innerHTML assignment",
				Location:    "script2.js:23",
			},
		},
	}

	// Update job with result
	s.mu.Lock()
	job.Status = "completed"
	job.Progress = 100
	job.Result = result
	s.mu.Unlock()

	s.log.Info("Scan job completed", "job_id", job.ID)
}
