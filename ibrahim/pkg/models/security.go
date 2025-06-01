package models

import "time"

// SecurityVulnerability represents a security vulnerability in a JavaScript application
// It's separate from the Finding type but can be linked to findings
type SecurityVulnerability struct {
	// ID is the unique identifier of the vulnerability
	ID string `json:"id"`

	// Name is the name of the vulnerability
	Name string `json:"name"`

	// Description is the description of the vulnerability
	Description string `json:"description"`

	// Severity is the severity of the vulnerability
	Severity Severity `json:"severity"`

	// CVEID is the CVE ID of the vulnerability if available
	CVEID string `json:"cve_id,omitempty"`

	// Package is the name of the package with the vulnerability
	Package string `json:"package"`

	// Version is the version of the package with the vulnerability
	Version string `json:"version"`

	// AffectedVersions is the range of affected versions
	AffectedVersions string `json:"affected_versions"`

	// FixedVersion is the version that fixes the vulnerability
	FixedVersion string `json:"fixed_version,omitempty"`

	// References contains URLs to references about the vulnerability
	References []string `json:"references,omitempty"`

	// DiscoveredAt is the time when the vulnerability was discovered
	DiscoveredAt time.Time `json:"discovered_at"`
}

// NewSecurityVulnerability creates a new security vulnerability
func NewSecurityVulnerability(name string, packageName string, version string, severity Severity) *SecurityVulnerability {
	return &SecurityVulnerability{
		ID:           "VUL-" + time.Now().Format("20060102-150405"),
		Name:         name,
		Package:      packageName,
		Version:      version,
		Severity:     severity,
		DiscoveredAt: time.Now(),
	}
}

// SecurityReport represents a detailed security report for a JavaScript application
type SecurityReport struct {
	// ID is the unique identifier of the report
	ID string `json:"id"`

	// TargetURL is the URL of the target application
	TargetURL string `json:"target_url"`

	// Findings contains security findings
	Findings []*Finding `json:"findings"`

	// Vulnerabilities is the list of discovered vulnerabilities
	Vulnerabilities []*SecurityVulnerability `json:"vulnerabilities"`

	// Summary is the summary of the report
	Summary *SecurityReportSummary `json:"summary"`

	// CreatedAt is the time when the report was created
	CreatedAt time.Time `json:"created_at"`
}

// SecurityReportSummary represents a summary of a security report
type SecurityReportSummary struct {
	// TotalFindings is the total number of findings
	TotalFindings int `json:"total_findings"`

	// TotalVulnerabilities is the total number of vulnerabilities
	TotalVulnerabilities int `json:"total_vulnerabilities"`

	// CriticalCount is the number of critical severity findings
	CriticalCount int `json:"critical_count"`

	// HighCount is the number of high severity findings
	HighCount int `json:"high_count"`

	// MediumCount is the number of medium severity findings
	MediumCount int `json:"medium_count"`

	// LowCount is the number of low severity findings
	LowCount int `json:"low_count"`

	// InfoCount is the number of informational findings
	InfoCount int `json:"info_count"`

	// Score is the overall security score (0-100)
	Score float64 `json:"score"`
}
