package analyzer

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// BundleAnalyzer analyzes JavaScript bundles
type BundleAnalyzer struct {
	log *logger.Logger
}

// AnalyzeResult represents the result of analyzing a JavaScript bundle
type AnalyzeResult struct {
	ID              string                 `json:"id"`
	URL             string                 `json:"url"`
	BundleType      string                 `json:"bundle_type"`
	IsMinified      bool                   `json:"is_minified"`
	Size            int                    `json:"size"`
	Dependencies    []models.Dependency    `json:"dependencies"`
	Frameworks      []string               `json:"frameworks"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	AnalyzedAt      time.Time              `json:"analyzed_at"`
	Duration        time.Duration          `json:"duration"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// NewBundleAnalyzer creates a new bundle analyzer
func NewBundleAnalyzer(log *logger.Logger) *BundleAnalyzer {
	return &BundleAnalyzer{
		log: log,
	}
}

// Analyze analyzes a JavaScript bundle
func (a *BundleAnalyzer) Analyze(ctx context.Context, target *models.Target) (*AnalyzeResult, error) {
	a.log.Info("Analyzing JavaScript bundle", "url", target.URL)

	startTime := time.Now()

	// Create result
	result := &AnalyzeResult{
		ID:              target.Domain,
		URL:             target.URL,
		Dependencies:    make([]models.Dependency, 0),
		Frameworks:      make([]string, 0),
		Vulnerabilities: make([]models.Vulnerability, 0),
		AnalyzedAt:      startTime,
		Metadata:        make(map[string]interface{}),
	}

	// Process each script
	for _, script := range target.Scripts {
		// Detect bundle type
		bundleType := a.detectBundleType(script)
		if bundleType != "unknown" {
			result.BundleType = bundleType
		}

		// Check if minified
		if a.isMinified(script) {
			result.IsMinified = true
		}

		// Set size
		result.Size += len(script)

		// Extract dependencies
		deps := a.extractDependencies(script)
		result.Dependencies = append(result.Dependencies, deps...)

		// Detect frameworks
		frameworks := a.detectFrameworks(script)
		result.Frameworks = append(result.Frameworks, frameworks...)

		// Scan for vulnerabilities
		vulns := a.scanVulnerabilities(script)
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	// Calculate duration
	result.Duration = time.Since(startTime)

	a.log.Info("Bundle analysis completed",
		"url", target.URL,
		"bundle_type", result.BundleType,
		"dependencies", len(result.Dependencies),
		"vulnerabilities", len(result.Vulnerabilities),
		"duration", result.Duration,
	)

	return result, nil
}

// detectBundleType detects the type of JavaScript bundle
func (a *BundleAnalyzer) detectBundleType(script string) string {
	if strings.Contains(script, "__webpack_require__") {
		return "webpack"
	} else if strings.Contains(script, "ROLLUP_CHUNK_ID") || strings.Contains(script, "this.Rollup") {
		return "rollup"
	} else if strings.Contains(script, "define.amd") {
		return "requirejs"
	} else if strings.Contains(script, "System.register") {
		return "systemjs"
	} else if strings.Contains(script, "Parcel") {
		return "parcel"
	} else if strings.Contains(script, "Browserify") {
		return "browserify"
	}
	return "unknown"
}

// isMinified checks if a script is minified
func (a *BundleAnalyzer) isMinified(script string) bool {
	// Check if the script is minified based on various heuristics
	lines := strings.Split(script, "\n")

	// If it's a single line and long, it's likely minified
	if len(lines) < 5 && len(script) > 1000 {
		return true
	}

	// If the average line length is very high, it's likely minified
	var totalLength int
	for _, line := range lines {
		totalLength += len(line)
	}

	avgLineLength := float64(totalLength) / float64(len(lines))
	if avgLineLength > 200 {
		return true
	}

	// If there are a lot of semicolons in proportion to newlines, it's likely minified
	semicolons := strings.Count(script, ";")
	if float64(semicolons)/float64(len(lines)) > 5 {
		return true
	}

	return false
}

// extractDependencies extracts dependencies from a script
func (a *BundleAnalyzer) extractDependencies(script string) []models.Dependency {
	deps := make([]models.Dependency, 0)

	// Regular expressions for finding dependencies
	importRegex := regexp.MustCompile(`(?:import|from)\s+['"]([^'"]+)['"]`)
	requireRegex := regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// Find import statements
	importMatches := importRegex.FindAllStringSubmatch(script, -1)
	for _, match := range importMatches {
		if len(match) > 1 {
			deps = append(deps, models.Dependency{Name: match[1]})
		}
	}

	// Find require statements
	requireMatches := requireRegex.FindAllStringSubmatch(script, -1)
	for _, match := range requireMatches {
		if len(match) > 1 {
			deps = append(deps, models.Dependency{Name: match[1]})
		}
	}

	return deps
}

// detectFrameworks detects JavaScript frameworks used in a script
func (a *BundleAnalyzer) detectFrameworks(script string) []string {
	frameworks := make([]string, 0)

	// Common frameworks and their signatures
	frameworkSignatures := map[string][]string{
		"react":             {"React.createElement", "React.Component", "ReactDOM"},
		"vue":               {"Vue.component", "Vue.directive", "new Vue"},
		"angular":           {"angular.module", "ng-app", "ng-controller"},
		"jquery":            {"jQuery", "$(", "$.ajax"},
		"lodash":            {"_.map", "_.filter", "_.reduce"},
		"backbone":          {"Backbone.Model", "Backbone.Collection", "Backbone.View"},
		"ember":             {"Ember.Application", "Ember.Route", "Ember.Component"},
		"svelte":            {"svelte", "SvelteComponent"},
		"preact":            {"preact", "h(", "Preact"},
		"nextjs":            {"next/router", "next/link", "Next.js"},
		"gatsby":            {"gatsby", "graphql`"},
		"bootstrap":         {"bootstrap", "data-bs-", "data-toggle"},
		"tailwind":          {"tailwind", "tw-"},
		"material-ui":       {"@material-ui", "@mui"},
		"styled-components": {"styled-components", "styled.div", "styled("},
	}

	// Check for each framework
	for framework, signatures := range frameworkSignatures {
		for _, signature := range signatures {
			if strings.Contains(script, signature) {
				frameworks = append(frameworks, framework)
				break
			}
		}
	}

	return frameworks
}

// scanVulnerabilities scans for vulnerabilities in a script
func (a *BundleAnalyzer) scanVulnerabilities(script string) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)

	// Check for common vulnerabilities

	// eval - Code injection
	if strings.Contains(script, "eval(") {
		vuln := models.Vulnerability{
			Type:        "eval",
			Severity:    "high",
			Description: "Direct eval usage found, which can lead to code injection vulnerabilities",
		}
		vulns = append(vulns, vuln)
	}

	// document.write - XSS
	if strings.Contains(script, "document.write(") {
		vuln := models.Vulnerability{
			Type:        "document.write",
			Severity:    "medium",
			Description: "document.write usage found, which can lead to XSS vulnerabilities",
		}
		vulns = append(vulns, vuln)
	}

	// innerHTML - XSS
	if regexp.MustCompile(`(\W|^)innerHTML\s*=`).MatchString(script) {
		vuln := models.Vulnerability{
			Type:        "innerHTML",
			Severity:    "medium",
			Description: "innerHTML usage found, which can lead to XSS vulnerabilities",
		}
		vulns = append(vulns, vuln)
	}

	// new Function - Code injection
	if strings.Contains(script, "new Function(") {
		vuln := models.Vulnerability{
			Type:        "Function",
			Severity:    "high",
			Description: "Dynamic Function creation found, which can lead to code injection vulnerabilities",
		}
		vulns = append(vulns, vuln)
	}

	// setTimeout/setInterval with string - Code injection
	if regexp.MustCompile(`set(Timeout|Interval)\s*\(\s*['"]`).MatchString(script) {
		vuln := models.Vulnerability{
			Type:        "setTimeout",
			Severity:    "medium",
			Description: "setTimeout/setInterval with string argument found, which can lead to code injection",
		}
		vulns = append(vulns, vuln)
	}

	return vulns
}
