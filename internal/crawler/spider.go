package crawler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/ibrahimsql/spiderjs/internal/config"
	customhttp "github.com/ibrahimsql/spiderjs/internal/utils/http"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// Spider is a web crawler for JavaScript applications
type Spider struct {
	config    *config.Config
	client    *customhttp.Client
	log       *logger.Logger
	target    *models.Target
	visited   map[string]bool
	mutex     sync.Mutex
	semaphore chan struct{}
}

// NewSpider creates a new Spider instance
func NewSpider(ctx context.Context, cfg *config.Config, log *logger.Logger) (*Spider, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if cfg.URL == "" {
		return nil, errors.New("URL cannot be empty")
	}

	var err error

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered in NewSpider: %v", r)
		}
	}()

	// Create HTTP client
	clientOptions := &customhttp.ClientOptions{
		Timeout:       cfg.Timeout,
		UserAgent:     cfg.UserAgent,
		Proxy:         cfg.Proxy,
		SkipTLSVerify: cfg.SkipTLSVerify,
	}

	client, err := customhttp.NewClient(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Create target
	target, err := models.NewTarget(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}

	return &Spider{
		config:    cfg,
		client:    client,
		log:       log,
		target:    target,
		visited:   make(map[string]bool),
		semaphore: make(chan struct{}, cfg.Concurrent),
	}, nil
}

// Crawl starts crawling the target using Katana library
func (s *Spider) Crawl(ctx context.Context) (*models.Target, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic recovered in Crawl: %v", r)
			s.log.ErrorMsg("Crawler panic: %v", err)
		}
	}()

	s.log.Success("Starting advanced crawl of %s", s.target.URL)
	startTime := time.Now()

	// Configure Katana crawler options
	options := &types.Options{
		MaxDepth:     s.config.MaxDepth,
		FieldScope:   "rdn",                           // Crawling Scope Field (root domain name)
		BodyReadSize: math.MaxInt,                     // Maximum response size to read
		Timeout:      int(s.config.Timeout.Seconds()), // Timeout in seconds
		Concurrency:  s.config.Concurrent,             // Concurrent crawling goroutines
		Parallelism:  s.config.Concurrent,             // Parallel URL processing goroutines
		Delay:        0,                               // No delay between requests
		RateLimit:    150,                             // Maximum requests per second
		Strategy:     "depth-first",                   // Visit strategy
		OnResult: func(result output.Result) {
			// Process each crawled URL
			s.processKatanaResult(ctx, result)
		},
	}

	// Setup additional options based on config
	if s.config.ScanOptions.IncludeSubdomains {
		options.FieldScope = "fqdn" // Full qualified domain name to include subdomains
	}

	// Initialize Katana crawler
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create crawler options: %w", err)
	}
	defer crawlerOptions.Close()

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create crawler: %w", err)
	}
	defer crawler.Close()

	// Start crawling
	err = crawler.Crawl(s.target.URL)
	if err != nil {
		s.log.ErrorMsg("Crawler error: %v", err)
		// Continue with partial results if available
	}

	// Log results
	duration := time.Since(startTime)
	s.log.Success("Crawl completed in %s", duration)
	s.log.Success("Visited %d URLs", len(s.visited))
	s.log.Success("Found %d scripts", len(s.target.Scripts))
	s.log.Success("Found %d APIs", len(s.target.APIs))

	return s.target, nil
}

// processKatanaResult processes a single result from Katana crawler
func (s *Spider) processKatanaResult(ctx context.Context, result output.Result) {
	// Check context
	if ctx.Err() != nil {
		return
	}

	urlStr := result.Request.URL

	// Skip if already visited
	if s.isVisited(urlStr) {
		return
	}

	// Mark as visited
	s.markVisited(urlStr)

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		s.log.ErrorMsg("Failed to parse URL %s: %v", urlStr, err)
		return
	}

	// Add path to target
	s.target.AddPath(parsedURL.Path)

	// Extract headers from response
	for key, values := range result.Response.Headers {
		if len(values) > 0 {
			s.target.AddHeader(key, string(values[0]))
		}
	}

	// Process JavaScript files
	if strings.HasSuffix(parsedURL.Path, ".js") ||
		strings.HasSuffix(parsedURL.Path, ".jsx") ||
		strings.HasSuffix(parsedURL.Path, ".ts") ||
		strings.HasSuffix(parsedURL.Path, ".tsx") {
		s.target.AddScript(urlStr)
	}

	// Process potential API endpoints
	if isAPIEndpoint(parsedURL.Path) {
		s.target.AddAPI(urlStr)
	}

	// Process HTML content for additional extraction
	if result.Response.StatusCode == http.StatusOK {
		contentType := ""
		if values, ok := result.Response.Headers["Content-Type"]; ok && len(values) > 0 {
			contentType = string(values[0])
		}
		if strings.Contains(contentType, "text/html") {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(result.Response.Body))
			if err == nil {
				// Extract scripts
				doc.Find("script").Each(func(i int, sel *goquery.Selection) {
					src, exists := sel.Attr("src")
					if exists {
						// Resolve relative URL
						resolvedURL, err := resolveURL(urlStr, src)
						if err == nil {
							s.target.AddScript(resolvedURL)
						}
					}
				})

				// Extract forms
				doc.Find("form").Each(func(i int, sel *goquery.Selection) {
					action, exists := sel.Attr("action")
					if exists {
						// Resolve relative URL
						resolvedURL, err := resolveURL(urlStr, action)
						if err == nil {
							s.target.AddAPI(resolvedURL)
						}
					}
				})
			}
		}
	}
}

// isVisited checks if a URL has been visited
func (s *Spider) isVisited(url string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.visited[url]
}

// markVisited marks a URL as visited
func (s *Spider) markVisited(url string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.visited[url] = true
}

// isAPIEndpoint checks if a path is likely an API endpoint
func isAPIEndpoint(path string) bool {
	apiPatterns := []string{
		"/api/",
		"/rest/",
		"/graphql",
		"/v1/",
		"/v2/",
		"/v3/",
		"/service/",
		".json",
		".xml",
	}

	for _, pattern := range apiPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// resolveURL resolves a relative URL against a base URL
func resolveURL(base, ref string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}

	resolvedURL := baseURL.ResolveReference(refURL)
	return resolvedURL.String(), nil
}
