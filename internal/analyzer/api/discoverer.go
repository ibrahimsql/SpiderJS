package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// EndpointType represents the type of API endpoint
type EndpointType string

const (
	// EndpointTypeREST represents a REST API endpoint
	EndpointTypeREST EndpointType = "rest"
	// EndpointTypeGraphQL represents a GraphQL API endpoint
	EndpointTypeGraphQL EndpointType = "graphql"
	// EndpointTypeWebSocket represents a WebSocket API endpoint
	EndpointTypeWebSocket EndpointType = "websocket"
	// EndpointTypeSSE represents a Server-Sent Events API endpoint
	EndpointTypeSSE EndpointType = "sse"
)

// Endpoint represents an API endpoint
type Endpoint struct {
	URL         string       `json:"url"`
	Type        EndpointType `json:"type"`
	Method      string       `json:"method,omitempty"`
	Description string       `json:"description,omitempty"`
	Parameters  []string     `json:"parameters,omitempty"`
	Headers     []string     `json:"headers,omitempty"`
	Score       int          `json:"score"`
}

// Discoverer discovers API endpoints in web applications
type Discoverer struct {
	log *logger.Logger
}

// NewDiscoverer creates a new API discoverer
func NewDiscoverer(log *logger.Logger) (*Discoverer, error) {
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	return &Discoverer{
		log: log,
	}, nil
}

// Discover discovers API endpoints from an HTTP response
func (d *Discoverer) Discover(ctx context.Context, resp *http.Response, baseURL string) ([]*Endpoint, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if resp == nil {
		return nil, errors.New("response cannot be nil")
	}

	if baseURL == "" {
		return nil, errors.New("base URL cannot be empty")
	}

	var endpoints []*Endpoint

	// Parse the base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Check for GraphQL endpoints
	graphQLEndpoints, err := d.discoverGraphQL(resp, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover GraphQL endpoints: %w", err)
	}
	endpoints = append(endpoints, graphQLEndpoints...)

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Discover REST endpoints from script tags
	restEndpoints, err := d.discoverRESTFromScripts(doc, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover REST endpoints from scripts: %w", err)
	}
	endpoints = append(endpoints, restEndpoints...)

	// Discover WebSocket endpoints
	wsEndpoints, err := d.discoverWebSockets(doc, base)
	if err != nil {
		return nil, fmt.Errorf("failed to discover WebSocket endpoints: %w", err)
	}
	endpoints = append(endpoints, wsEndpoints...)

	return endpoints, nil
}

// DiscoverFromTarget discovers API endpoints from a target
func (d *Discoverer) DiscoverFromTarget(ctx context.Context, target *models.Target) ([]*Endpoint, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	var endpoints []*Endpoint

	// Check for API paths
	for _, path := range target.Paths {
		// Check for REST API patterns
		if d.isRESTPath(path) {
			endpoint := &Endpoint{
				URL:    target.URL + path,
				Type:   EndpointTypeREST,
				Method: "GET",
				Score:  70,
			}
			endpoints = append(endpoints, endpoint)
		}

		// Check for GraphQL endpoints
		if d.isGraphQLPath(path) {
			endpoint := &Endpoint{
				URL:    target.URL + path,
				Type:   EndpointTypeGraphQL,
				Method: "POST",
				Score:  90,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, nil
}

// discoverGraphQL discovers GraphQL endpoints
func (d *Discoverer) discoverGraphQL(resp *http.Response, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Check for GraphQL in response headers
	if strings.Contains(resp.Header.Get("Content-Type"), "application/graphql") {
		endpoint := &Endpoint{
			URL:    resp.Request.URL.String(),
			Type:   EndpointTypeGraphQL,
			Method: "POST",
			Score:  100,
		}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// discoverRESTFromScripts discovers REST endpoints from script tags
func (d *Discoverer) discoverRESTFromScripts(doc *goquery.Document, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Look for fetch or axios calls in script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		html, err := s.Html()
		if err != nil {
			return
		}

		// Look for fetch calls
		fetchRegex := regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`)
		fetchMatches := fetchRegex.FindAllStringSubmatch(html, -1)
		for _, match := range fetchMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:    d.resolveURL(baseURL, url),
						Type:   EndpointTypeREST,
						Method: "GET",
						Score:  80,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}

		// Look for axios calls
		axiosRegex := regexp.MustCompile(`axios\.(get|post|put|delete)\s*\(\s*["']([^"']+)["']`)
		axiosMatches := axiosRegex.FindAllStringSubmatch(html, -1)
		for _, match := range axiosMatches {
			if len(match) > 2 {
				method := strings.ToUpper(match[1])
				url := match[2]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:    d.resolveURL(baseURL, url),
						Type:   EndpointTypeREST,
						Method: method,
						Score:  90,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}

		// Look for API URLs in JSON objects
		apiRegex := regexp.MustCompile(`["']api["']\s*:\s*["']([^"']+)["']`)
		apiMatches := apiRegex.FindAllStringSubmatch(html, -1)
		for _, match := range apiMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:   d.resolveURL(baseURL, url),
						Type:  EndpointTypeREST,
						Score: 70,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	})

	return endpoints, nil
}

// discoverWebSockets discovers WebSocket endpoints
func (d *Discoverer) discoverWebSockets(doc *goquery.Document, baseURL *url.URL) ([]*Endpoint, error) {
	var endpoints []*Endpoint

	// Look for WebSocket connections in script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		html, err := s.Html()
		if err != nil {
			return
		}

		// Look for WebSocket constructor calls
		wsRegex := regexp.MustCompile(`new\s+WebSocket\s*\(\s*["']([^"']+)["']`)
		wsMatches := wsRegex.FindAllStringSubmatch(html, -1)
		for _, match := range wsMatches {
			if len(match) > 1 {
				url := match[1]
				if d.isValidURL(url) {
					endpoint := &Endpoint{
						URL:   url,
						Type:  EndpointTypeWebSocket,
						Score: 100,
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	})

	return endpoints, nil
}

// isRESTPath checks if a path looks like a REST API endpoint
func (d *Discoverer) isRESTPath(path string) bool {
	// Check for common REST API patterns
	patterns := []string{
		"/api/",
		"/rest/",
		"/v1/",
		"/v2/",
		"/v3/",
	}

	for _, pattern := range patterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// isGraphQLPath checks if a path looks like a GraphQL endpoint
func (d *Discoverer) isGraphQLPath(path string) bool {
	return strings.Contains(path, "/graphql") || strings.Contains(path, "/graphiql")
}

// isValidURL checks if a URL is valid
func (d *Discoverer) isValidURL(urlStr string) bool {
	// Skip data URLs and empty URLs
	if urlStr == "" || strings.HasPrefix(urlStr, "data:") {
		return false
	}

	// Skip anchor links
	if strings.HasPrefix(urlStr, "#") {
		return false
	}

	return true
}

// resolveURL resolves a URL against a base URL
func (d *Discoverer) resolveURL(base *url.URL, urlStr string) string {
	// Check if the URL is already absolute
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
		return urlStr
	}

	// Resolve relative URL
	rel, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	resolved := base.ResolveReference(rel)
	return resolved.String()
}
