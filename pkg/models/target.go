package models

import (
	"errors"
	"net/url"
	"time"
)

// Target represents a target application to scan
type Target struct {
	// URL is the base URL of the target
	URL       string   `json:"url"`
	ParsedURL *url.URL `json:"-"`

	// Domain is the domain of the target
	Domain string `json:"domain"`

	// Paths contains all discovered paths
	Paths []string `json:"paths,omitempty"`

	// Scripts contains all discovered JavaScript files
	Scripts []string `json:"scripts,omitempty"`

	// APIs contains all discovered API endpoints
	APIs []string `json:"apis,omitempty"`

	// Technologies contains detected technologies
	Technologies []string `json:"technologies,omitempty"`

	// Frameworks contains detected frameworks
	Frameworks []string `json:"frameworks,omitempty"`

	// Headers contains response headers
	Headers map[string]string `json:"headers,omitempty"`

	// Cookies contains cookies
	Cookies map[string]string `json:"cookies,omitempty"`

	// FirstSeen is when the target was first seen
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is when the target was last seen
	LastSeen time.Time `json:"last_seen"`

	Visited    map[string]bool `json:"-"`
	VisitQueue []string        `json:"-"`
}

// NewTarget creates a new target from a URL string
func NewTarget(urlStr string) (*Target, error) {
	if urlStr == "" {
		return nil, errors.New("URL cannot be empty")
	}

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		urlStr = parsedURL.String()
	}

	now := time.Now()

	return &Target{
		URL:        urlStr,
		ParsedURL:  parsedURL,
		Domain:     parsedURL.Hostname(),
		FirstSeen:  now,
		LastSeen:   now,
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
		Visited:    make(map[string]bool),
		VisitQueue: []string{},
	}, nil
}

// AddPath adds a path to the target
func (t *Target) AddPath(path string) {
	// Check if path already exists
	for _, p := range t.Paths {
		if p == path {
			return
		}
	}

	t.Paths = append(t.Paths, path)
}

// AddScript adds a script to the target
func (t *Target) AddScript(script string) {
	// Skip empty scripts
	if script == "" {
		return
	}

	// Skip duplicates
	for _, s := range t.Scripts {
		if s == script {
			return
		}
	}

	t.Scripts = append(t.Scripts, script)
}

// AddAPI adds an API endpoint to the target
func (t *Target) AddAPI(api string) {
	// Check if API already exists
	for _, a := range t.APIs {
		if a == api {
			return
		}
	}

	t.APIs = append(t.APIs, api)
}

// AddTechnology adds a technology to the target
func (t *Target) AddTechnology(tech string) {
	// Check if technology already exists
	for _, tech2 := range t.Technologies {
		if tech2 == tech {
			return
		}
	}

	t.Technologies = append(t.Technologies, tech)
}

// AddFramework adds a framework to the target
func (t *Target) AddFramework(framework string) {
	// Check if framework already exists
	for _, f := range t.Frameworks {
		if f == framework {
			return
		}
	}

	t.Frameworks = append(t.Frameworks, framework)
}

// AddHeader adds a header to the target
func (t *Target) AddHeader(name, value string) {
	t.Headers[name] = value
}

// AddCookie adds a cookie to the target
func (t *Target) AddCookie(name, value string) {
	t.Cookies[name] = value
}

// UpdateLastSeen updates the last seen timestamp
func (t *Target) UpdateLastSeen() {
	t.LastSeen = time.Now()
}

// MarkVisited marks a URL as visited
func (t *Target) MarkVisited(url string) {
	t.Visited[url] = true
}

// IsVisited checks if a URL has been visited
func (t *Target) IsVisited(url string) bool {
	return t.Visited[url]
}

// AddToQueue adds a URL to the visit queue
func (t *Target) AddToQueue(url string) {
	// Skip if already visited or in queue
	if t.IsVisited(url) {
		return
	}

	for _, u := range t.VisitQueue {
		if u == url {
			return
		}
	}

	t.VisitQueue = append(t.VisitQueue, url)
}

// GetNextURL gets the next URL from the queue
func (t *Target) GetNextURL() string {
	if len(t.VisitQueue) == 0 {
		return ""
	}

	url := t.VisitQueue[0]
	t.VisitQueue = t.VisitQueue[1:]
	return url
}

// QueueSize returns the size of the visit queue
func (t *Target) QueueSize() int {
	return len(t.VisitQueue)
}

// ScriptCount returns the number of scripts
func (t *Target) ScriptCount() int {
	return len(t.Scripts)
}
