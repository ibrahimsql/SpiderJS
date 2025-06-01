package models

import (
	"time"

	"github.com/google/uuid"
)

// Severity represents the severity level of a finding
type Severity string

const (
	// SeverityInfo represents an informational finding
	SeverityInfo Severity = "info"
	// SeverityLow represents a low severity finding
	SeverityLow Severity = "low"
	// SeverityMedium represents a medium severity finding
	SeverityMedium Severity = "medium"
	// SeverityHigh represents a high severity finding
	SeverityHigh Severity = "high"
	// SeverityCritical represents a critical severity finding
	SeverityCritical Severity = "critical"
)

// FindingType represents the type of finding
type FindingType string

const (
	// FindingTypeVulnerability represents a security vulnerability
	FindingTypeVulnerability FindingType = "vulnerability"
	// FindingTypeFramework represents a framework detection
	FindingTypeFramework FindingType = "framework"
	// FindingTypeAPI represents an API endpoint
	FindingTypeAPI FindingType = "api"
	// FindingTypeRoute represents an application route
	FindingTypeRoute FindingType = "route"
	// FindingTypeBundle represents a JavaScript bundle
	FindingTypeBundle FindingType = "bundle"
	// FindingTypeConfig represents a configuration issue
	FindingTypeConfig FindingType = "config"
	// FindingTypeXSS represents a cross-site scripting vulnerability
	FindingTypeXSS FindingType = "xss"
	// FindingTypeInjection represents an injection vulnerability
	FindingTypeInjection FindingType = "injection"
	// FindingTypeCSRF represents a cross-site request forgery vulnerability
	FindingTypeCSRF FindingType = "csrf"
	// FindingTypeCORS represents a CORS misconfiguration
	FindingTypeCORS FindingType = "cors"
	// FindingTypeHeader represents a security header issue
	FindingTypeHeader FindingType = "header"
	// FindingTypeCookie represents a cookie security issue
	FindingTypeCookie FindingType = "cookie"
	// FindingTypeSupplyChain represents a supply chain security issue
	FindingTypeSupplyChain FindingType = "supply_chain"
	// FindingTypePrototype represents a prototype pollution vulnerability
	FindingTypePrototype FindingType = "prototype"
)

// Finding represents a security finding or discovery
type Finding struct {
	ID          string      `json:"id"`
	Type        FindingType `json:"type"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	CVSS        float64     `json:"cvss,omitempty"`
	URL         string      `json:"url,omitempty"`
	Path        string      `json:"path,omitempty"`
	Evidence    string      `json:"evidence,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	References  []string    `json:"references,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewFinding creates a new finding
func NewFinding(findingType FindingType, title string, severity Severity) *Finding {
	return &Finding{
		ID:        uuid.New().String(),
		Type:      findingType,
		Title:     title,
		Severity:  severity,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
}

// WithDescription adds a description to the finding
func (f *Finding) WithDescription(description string) *Finding {
	f.Description = description
	return f
}

// WithURL adds a URL to the finding
func (f *Finding) WithURL(url string) *Finding {
	f.URL = url
	return f
}

// WithPath adds a path to the finding
func (f *Finding) WithPath(path string) *Finding {
	f.Path = path
	return f
}

// WithEvidence adds evidence to the finding
func (f *Finding) WithEvidence(evidence string) *Finding {
	f.Evidence = evidence
	return f
}

// WithRemediation adds remediation guidance to the finding
func (f *Finding) WithRemediation(remediation string) *Finding {
	f.Remediation = remediation
	return f
}

// WithReferences adds references to the finding
func (f *Finding) WithReferences(references ...string) *Finding {
	f.References = append(f.References, references...)
	return f
}

// WithTags adds tags to the finding
func (f *Finding) WithTags(tags ...string) *Finding {
	f.Tags = append(f.Tags, tags...)
	return f
}

// WithCVSS adds a CVSS score to the finding
func (f *Finding) WithCVSS(cvss float64) *Finding {
	f.CVSS = cvss
	return f
}

// WithMetadata adds metadata to the finding
func (f *Finding) WithMetadata(key string, value interface{}) *Finding {
	f.Metadata[key] = value
	return f
}
