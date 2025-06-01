package crawler

import (
	"context"
	"errors"
	"fmt"
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
)

// Spider is a web crawler for JavaScript applications
type Spider struct {
	config    *config.Config
	client    *customhttp.Client
	log       *logger.Logger
	target    *models.Target
	visited   map[string]bool
	queue     []string
	mutex     sync.Mutex
	wg        sync.WaitGroup
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

// Crawl starts crawling the target
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

	// Add initial URL to queue
	s.queue = append(s.queue, s.target.URL)

	// Start crawling
	s.log.Success("Starting crawl of %s", s.target.URL)
	startTime := time.Now()

	// Process queue
	for len(s.queue) > 0 && ctx.Err() == nil {
		// Get next URL from queue
		var url string
		s.mutex.Lock()
		url, s.queue = s.queue[0], s.queue[1:]
		s.mutex.Unlock()

		// Skip if already visited
		if s.isVisited(url) {
			continue
		}

		// Mark as visited
		s.markVisited(url)

		// Process URL
		s.wg.Add(1)
		s.semaphore <- struct{}{}
		go func(url string) {
			defer s.wg.Done()
			defer func() { <-s.semaphore }()

			s.processURL(ctx, url)
		}(url)
	}

	// Wait for all goroutines to finish
	s.wg.Wait()

	// Log results
	duration := time.Since(startTime)
	s.log.Success("Crawl completed in %s", duration)
	s.log.Success("Visited %d URLs", len(s.visited))
	s.log.Success("Found %d scripts", len(s.target.Scripts))
	s.log.Success("Found %d APIs", len(s.target.APIs))

	return s.target, nil
}

// processURL processes a single URL
func (s *Spider) processURL(ctx context.Context, urlStr string) {
	// Check context
	if ctx.Err() != nil {
		return
	}

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		s.log.ErrorMsg("Failed to parse URL %s: %v", urlStr, err)
		return
	}

	// Skip if not same domain
	if parsedURL.Hostname() != s.target.Domain && !s.config.ScanOptions.IncludeSubdomains {
		return
	}

	// Skip if depth exceeded
	depth := strings.Count(parsedURL.Path, "/")
	if depth > s.config.MaxDepth {
		return
	}

	// Fetch URL
	s.log.Success("Fetching %s", urlStr)
	resp, err := s.client.Get(ctx, urlStr)
	if err != nil {
		s.log.ErrorMsg("Failed to fetch %s: %v", urlStr, err)
		return
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		s.log.Warning("Got status %d for %s", resp.StatusCode, urlStr)
		return
	}

	// Add path to target
	s.target.AddPath(parsedURL.Path)

	// Extract headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			s.target.AddHeader(key, values[0])
		}
	}

	// Extract cookies
	for _, cookie := range resp.Cookies() {
		s.target.AddCookie(cookie.Name, cookie.Value)
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		s.log.ErrorMsg("Failed to parse HTML from %s: %v", urlStr, err)
		return
	}

	// Extract links
	doc.Find("a").Each(func(i int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists {
			return
		}

		// Resolve relative URL
		resolvedURL, err := resolveURL(urlStr, href)
		if err != nil {
			return
		}

		// Add to queue if not visited
		if !s.isVisited(resolvedURL) {
			s.addToQueue(resolvedURL)
		}
	})

	// Extract scripts
	doc.Find("script").Each(func(i int, sel *goquery.Selection) {
		src, exists := sel.Attr("src")
		if !exists {
			// Inline script
			return
		}

		// Resolve relative URL
		resolvedURL, err := resolveURL(urlStr, src)
		if err != nil {
			return
		}

		// Add to target
		s.target.AddScript(resolvedURL)
	})
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

// addToQueue adds a URL to the queue
func (s *Spider) addToQueue(url string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.queue = append(s.queue, url)
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
