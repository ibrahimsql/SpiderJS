package interfaces

import (
	"context"

	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// BundleAnalyzer defines the interface for JavaScript bundle analyzers
type BundleAnalyzer interface {
	// Analyze analyzes a JavaScript bundle and extracts information
	Analyze(ctx context.Context, target *models.Target) error

	// IsMinified checks if a JavaScript code is minified
	IsMinified(script string) bool

	// HasSourceMap checks if a JavaScript code has a source map
	HasSourceMap(script string) bool

	// ExtractDependencies extracts dependencies from a JavaScript code
	ExtractDependencies(script string) []string

	// DetectVersion tries to detect the version of a framework
	DetectVersion(script string, framework string) string

	// DetectBundleType detects the type of a JavaScript bundle
	DetectBundleType(script string) string
}

// FrameworkDetector defines the interface for JavaScript framework detectors
type FrameworkDetector interface {
	// Detect detects JavaScript frameworks used in a web application
	Detect(ctx context.Context, target *models.Target) error

	// DetectFromTarget detects JavaScript frameworks from an existing target
	DetectFromTarget(target *models.Target) error

	// DetectVersion tries to detect the version of a framework
	DetectVersion(script string, framework string) string

	// IsMetaFramework checks if a framework is a meta framework
	IsMetaFramework(framework string) bool
}

// APIDiscoverer defines the interface for API discoverers
type APIDiscoverer interface {
	// Discover discovers APIs in a web application
	Discover(ctx context.Context, target *models.Target) error

	// DiscoverFromTarget discovers APIs from an existing target
	DiscoverFromTarget(target *models.Target) error
}

// DependencyAnalyzer defines the interface for dependency analyzers
type DependencyAnalyzer interface {
	// AnalyzeDependencies analyzes the dependencies of a JavaScript application
	AnalyzeDependencies(ctx context.Context, target *models.Target) error

	// CheckVulnerabilities checks for vulnerabilities in dependencies
	CheckVulnerabilities(dependencies []string) []*models.SecurityVulnerability
}

// VulnerabilityScanner defines the interface for vulnerability scanners
type VulnerabilityScanner interface {
	// Scan scans a JavaScript application for vulnerabilities
	Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error)

	// GenerateReport generates a report of the scan results
	GenerateReport(findings []*models.Finding) *models.SecurityReport
}
