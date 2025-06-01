package models

import (
	"time"
)

// ScanResult represents the result of scanning a website for JavaScript
type ScanResult struct {
	URL             string                 `json:"url"`
	ScannedAt       time.Time              `json:"scanned_at"`
	CompletedAt     time.Time              `json:"completed_at"`
	ScriptsFound    int                    `json:"scripts_found"`
	ScriptsAnalyzed int                    `json:"scripts_analyzed"`
	BundleTypes     map[string]int         `json:"bundle_types"`
	Dependencies    []*Dependency          `json:"dependencies"`
	Vulnerabilities []*Vulnerability       `json:"vulnerabilities"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// NewScanResult creates a new scan result
func NewScanResult(url string) *ScanResult {
	return &ScanResult{
		URL:             url,
		ScannedAt:       time.Now(),
		BundleTypes:     make(map[string]int),
		Dependencies:    make([]*Dependency, 0),
		Vulnerabilities: make([]*Vulnerability, 0),
		Metadata:        make(map[string]interface{}),
	}
}

// AddDependency adds a dependency to the scan result
func (r *ScanResult) AddDependency(name, version string) {
	r.Dependencies = append(r.Dependencies, &Dependency{
		Name:    name,
		Version: version,
	})
}

// AddVulnerability adds a vulnerability to the scan result
func (r *ScanResult) AddVulnerability(vuln *Vulnerability) {
	r.Vulnerabilities = append(r.Vulnerabilities, vuln)
}

// MarkComplete marks the scan as complete
func (r *ScanResult) MarkComplete() {
	r.CompletedAt = time.Now()
}

// ScanStatus represents the status of a scan
type ScanStatus string

// Scan status constants
const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)
