package analyzer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/analyzer/bundle"
	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// Analyzer is responsible for analyzing JavaScript code
type Analyzer struct {
	config *config.Config
	log    *logger.Logger
	bundle *bundle.Analyzer
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(ctx context.Context, cfg *config.Config, log *logger.Logger) (*Analyzer, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	// Create bundle analyzer
	bundleAnalyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle analyzer: %w", err)
	}

	return &Analyzer{
		config: cfg,
		log:    log,
		bundle: bundleAnalyzer,
	}, nil
}

// Analyze analyzes a JavaScript target
func (a *Analyzer) Analyze(ctx context.Context, target *models.Target) (*models.AnalysisResult, error) {
	// Context timeout check
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Input validation
	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	// Start analysis
	a.log.Info("Starting analysis", "target", target.URL)
	startTime := time.Now()

	// Create result
	result := models.NewAnalysisResult(target)

	// Check if target is a file
	fileInfo, err := os.Stat(target.URL)
	if err == nil && !fileInfo.IsDir() {
		// Load file content
		content, err := os.ReadFile(target.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		// Set file size
		result.SetFileSize(fileInfo.Size())

		// Add script to target
		target.Scripts = []string{string(content)}
	}

	// Analyze bundle if scripts are available
	if len(target.Scripts) > 0 {
		bundleInfos, err := a.bundle.Analyze(ctx, target)
		if err != nil {
			a.log.Warn("Bundle analysis failed", "error", err)
		} else {
			// Process bundle information
			for _, info := range bundleInfos {
				// Set bundle type if found
				if info.Type != bundle.Unknown && result.BundleType == "" {
					result.SetBundleType(string(info.Type))
				}

				// Set minified flag if detected
				if info.IsMinified {
					result.SetIsMinified(true)
				}

				// Add dependencies
				for _, dep := range info.Dependencies {
					// Extract name and version (if available)
					parts := splitDependency(dep)
					if len(parts) > 1 {
						result.AddDependency(parts[0], parts[1])
					} else {
						result.AddDependency(parts[0], "")
					}
				}
			}
		}
	}

	// Detect frameworks
	a.detectFrameworks(result)

	// Check for vulnerabilities if enabled
	if a.config.AnalyzerOptions.CheckVulnerabilities {
		a.scanVulnerabilities(result)
	}

	// Set duration
	duration := time.Since(startTime)
	result.SetDuration(duration.String())
	result.SetScriptCount(len(target.Scripts))

	// Log analysis completion
	a.log.Success("Analysis completed", "duration", duration.String())
	return result, nil
}

// detectFrameworks detects JavaScript frameworks in the analysis result
func (a *Analyzer) detectFrameworks(result *models.AnalysisResult) {
	// Simple framework detection based on dependencies
	frameworkPatterns := map[string]string{
		"react":             "React",
		"angular":           "Angular",
		"vue":               "Vue.js",
		"ember":             "Ember.js",
		"backbone":          "Backbone.js",
		"jquery":            "jQuery",
		"lodash":            "Lodash",
		"underscore":        "Underscore.js",
		"moment":            "Moment.js",
		"axios":             "Axios",
		"express":           "Express",
		"koa":               "Koa",
		"nextjs":            "Next.js",
		"next":              "Next.js",
		"gatsby":            "Gatsby",
		"nuxt":              "Nuxt.js",
		"svelte":            "Svelte",
		"preact":            "Preact",
		"redux":             "Redux",
		"mobx":              "MobX",
		"styled-components": "Styled Components",
		"tailwindcss":       "Tailwind CSS",
		"bootstrap":         "Bootstrap",
		"material-ui":       "Material-UI",
		"ant-design":        "Ant Design",
		"chakra-ui":         "Chakra UI",
		"graphql":           "GraphQL",
		"apollo":            "Apollo",
		"typescript":        "TypeScript",
		"webpack":           "Webpack",
		"rollup":            "Rollup",
		"vite":              "Vite",
		"parcel":            "Parcel",
		"babel":             "Babel",
		"eslint":            "ESLint",
		"jest":              "Jest",
		"mocha":             "Mocha",
		"chai":              "Chai",
		"cypress":           "Cypress",
	}

	// Check dependencies for known frameworks
	for _, dep := range result.Dependencies {
		for pattern, framework := range frameworkPatterns {
			if contains(dep.Name, pattern) {
				// Check if framework is already added
				alreadyAdded := false
				for _, fw := range result.Frameworks {
					if fw.Name == framework {
						alreadyAdded = true
						break
					}
				}

				if !alreadyAdded {
					result.AddFramework(framework, dep.Version)
				}
			}
		}
	}
}

// scanVulnerabilities scans for vulnerabilities in the JavaScript code
func (a *Analyzer) scanVulnerabilities(result *models.AnalysisResult) {
	// Check for common JavaScript vulnerabilities in the scripts
	vulnerabilityPatterns := map[string]struct {
		pattern  string
		severity string
		desc     string
	}{
		"eval": {
			pattern:  "eval\\(",
			severity: "High",
			desc:     "Use of eval() can lead to code injection vulnerabilities",
		},
		"document.write": {
			pattern:  "document\\.write\\(",
			severity: "Medium",
			desc:     "Use of document.write() can lead to XSS vulnerabilities",
		},
		"innerHTML": {
			pattern:  "\\.innerHTML\\s*=",
			severity: "Medium",
			desc:     "Assignment to innerHTML can lead to XSS vulnerabilities",
		},
		"Function constructor": {
			pattern:  "new\\s+Function\\(",
			severity: "High",
			desc:     "Use of Function constructor can lead to code injection vulnerabilities",
		},
		"setTimeout string": {
			pattern:  "setTimeout\\(\\s*['\"]",
			severity: "Medium",
			desc:     "Using strings with setTimeout() can lead to code injection",
		},
		"setInterval string": {
			pattern:  "setInterval\\(\\s*['\"]",
			severity: "Medium",
			desc:     "Using strings with setInterval() can lead to code injection",
		},
		"Insecure postMessage": {
			pattern:  "postMessage\\([^,]+,\\s*['\"]\\*['\"]\\)",
			severity: "Medium",
			desc:     "Insecure use of postMessage with wildcard origin",
		},
		"localStorage clear": {
			pattern:  "localStorage\\.clear\\(\\)",
			severity: "Low",
			desc:     "Clearing localStorage can lead to data loss",
		},
		"Hardcoded credentials": {
			pattern:  "(password|token|key|secret|credential)\\s*=\\s*['\"][^'\"]+['\"]",
			severity: "High",
			desc:     "Hardcoded credentials detected",
		},
		"Console logging": {
			pattern:  "console\\.(log|warn|error)\\(",
			severity: "Low",
			desc:     "Console logging found in production code",
		},
	}

	// Scan scripts for vulnerability patterns
	for _, script := range result.Target.Scripts {
		// Skip empty scripts
		if len(script) == 0 {
			continue
		}

		// Check for vulnerabilities
		for vulnType, vulnInfo := range vulnerabilityPatterns {
			locations := findPattern(script, vulnInfo.pattern)
			for _, loc := range locations {
				result.AddVulnerability(vulnType, vulnInfo.severity, vulnInfo.desc, loc)
			}
		}
	}
}

// Helper functions

// splitDependency splits a dependency string into name and version
func splitDependency(dep string) []string {
	// Common patterns: name@version, name:version, name version
	for _, sep := range []string{"@", ":", " "} {
		parts := split(dep, sep)
		if len(parts) > 1 {
			return parts
		}
	}
	return []string{dep}
}

// split splits a string by a separator and returns a slice of the parts
func split(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range filepath.SplitList(s) {
		parts = append(parts, part)
	}
	return parts
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return s == substr || len(s) >= len(substr) && s[:len(substr)] == substr || len(s) >= len(substr) && s[len(s)-len(substr):] == substr || len(s) >= len(substr) && contains(s[1:], substr)
}

// findPattern finds a pattern in a string and returns the locations
func findPattern(s, pattern string) []string {
	// TODO: Implement proper regex pattern matching with line numbers
	return []string{"unknown"}
}
