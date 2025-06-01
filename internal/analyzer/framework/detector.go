package framework

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// FrameworkType represents a JavaScript framework type
type FrameworkType string

// Framework types
const (
	React   FrameworkType = "react"
	Vue     FrameworkType = "vue"
	Angular FrameworkType = "angular"
	Svelte  FrameworkType = "svelte"
	NextJS  FrameworkType = "nextjs"
	NuxtJS  FrameworkType = "nuxtjs"
	Gatsby  FrameworkType = "gatsby"
	Remix   FrameworkType = "remix"
	SolidJS FrameworkType = "solidjs"
	Qwik    FrameworkType = "qwik"
	Unknown FrameworkType = "unknown"
)

// FrameworkInfo contains information about a detected framework
type FrameworkInfo struct {
	Type    FrameworkType `json:"type"`
	Version string        `json:"version,omitempty"`
	Meta    bool          `json:"meta,omitempty"`
	Score   float64       `json:"score"`
}

// Detector is responsible for detecting JavaScript frameworks
type Detector struct {
	log *logger.Logger
}

// NewDetector creates a new framework detector
func NewDetector(log *logger.Logger) (*Detector, error) {
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	return &Detector{
		log: log,
	}, nil
}

// Detect detects frameworks in the given target
func (d *Detector) Detect(ctx context.Context, target *models.Target) ([]*FrameworkInfo, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	// Initialize frameworks map to store detection scores
	frameworkScores := make(map[FrameworkType]float64)

	// Check scripts for framework signatures
	for _, script := range target.Scripts {
		d.detectFromScript(script, frameworkScores)
	}

	// Convert scores to framework info
	var frameworks []*FrameworkInfo
	for framework, score := range frameworkScores {
		if score > 0.3 { // Threshold for detection
			info := &FrameworkInfo{
				Type:  framework,
				Score: score,
			}

			// Try to detect version
			info.Version = d.detectVersion(framework, target)

			// Check if it's a meta-framework
			info.Meta = d.isMetaFramework(framework)

			frameworks = append(frameworks, info)
		}
	}

	return frameworks, nil
}

// DetectFromTarget detects frameworks from a target
func (d *Detector) DetectFromTarget(ctx context.Context, target *models.Target) ([]*FrameworkInfo, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	var frameworks []*FrameworkInfo

	// Check headers for framework signatures
	if target.Headers != nil {
		// Check for Next.js
		if server, ok := target.Headers["X-Powered-By"]; ok && strings.Contains(server, "Next.js") {
			frameworks = append(frameworks, &FrameworkInfo{
				Type:  NextJS,
				Score: 100,
			})
		}

		// Check for Nuxt.js
		if server, ok := target.Headers["Server"]; ok && strings.Contains(server, "Nuxt") {
			frameworks = append(frameworks, &FrameworkInfo{
				Type:  NuxtJS,
				Score: 100,
			})
		}
	}

	// Check scripts for framework signatures
	for _, script := range target.Scripts {
		// Check for React
		if strings.Contains(script, "react") {
			frameworks = append(frameworks, &FrameworkInfo{
				Type:  React,
				Score: 80,
			})
		}

		// Check for Vue
		if strings.Contains(script, "vue") {
			frameworks = append(frameworks, &FrameworkInfo{
				Type:  Vue,
				Score: 80,
			})
		}

		// Check for Angular
		if strings.Contains(script, "angular") {
			frameworks = append(frameworks, &FrameworkInfo{
				Type:  Angular,
				Score: 80,
			})
		}

		// Check for Svelte
		if strings.Contains(script, "svelte") {
			frameworks = append(frameworks, &FrameworkInfo{
				Type:  Svelte,
				Score: 80,
			})
		}
	}

	return frameworks, nil
}

// detectFromHTML detects frameworks from HTML content
func (d *Detector) detectFromHTML(html string, scores map[FrameworkType]float64) {
	// React detection
	if strings.Contains(html, "data-reactroot") || strings.Contains(html, "react-root") {
		scores[React] += 0.8
	}

	// Vue detection
	if strings.Contains(html, "data-v-") || strings.Contains(html, "__vue__") {
		scores[Vue] += 0.8
	}

	// Angular detection
	if strings.Contains(html, "ng-app") || strings.Contains(html, "ng-controller") || strings.Contains(html, "_nghost") {
		scores[Angular] += 0.8
	}

	// Svelte detection
	if strings.Contains(html, "__svelte") || strings.Contains(html, "svelte-") {
		scores[Svelte] += 0.8
	}

	// Next.js detection
	if strings.Contains(html, "__NEXT_DATA__") || strings.Contains(html, "next-page") {
		scores[NextJS] += 0.8
		scores[React] += 0.5 // Next.js is based on React
	}

	// Nuxt.js detection
	if strings.Contains(html, "__NUXT__") || strings.Contains(html, "nuxt-link") {
		scores[NuxtJS] += 0.8
		scores[Vue] += 0.5 // Nuxt.js is based on Vue
	}

	// Gatsby detection
	if strings.Contains(html, "___gatsby") || strings.Contains(html, "gatsby-") {
		scores[Gatsby] += 0.8
		scores[React] += 0.5 // Gatsby is based on React
	}

	// Remix detection
	if strings.Contains(html, "remix:") || strings.Contains(html, "data-remix-") {
		scores[Remix] += 0.8
		scores[React] += 0.5 // Remix is based on React
	}

	// SolidJS detection
	if strings.Contains(html, "solid-js") || strings.Contains(html, "_$HY") {
		scores[SolidJS] += 0.8
	}

	// Qwik detection
	if strings.Contains(html, "q:container") || strings.Contains(html, "qwik") {
		scores[Qwik] += 0.8
	}
}

// detectFromScript detects frameworks from JavaScript code
func (d *Detector) detectFromScript(script string, scores map[FrameworkType]float64) {
	// React detection
	if strings.Contains(script, "React.") || strings.Contains(script, "ReactDOM.") {
		scores[React] += 0.7
	}
	if strings.Contains(script, "useState") && strings.Contains(script, "useEffect") {
		scores[React] += 0.6
	}

	// Vue detection
	if strings.Contains(script, "Vue.") || strings.Contains(script, "createApp") {
		scores[Vue] += 0.7
	}
	if strings.Contains(script, "computed") && strings.Contains(script, "watch") {
		scores[Vue] += 0.6
	}

	// Angular detection
	if strings.Contains(script, "angular.") || strings.Contains(script, "@angular/core") {
		scores[Angular] += 0.7
	}
	if strings.Contains(script, "@Component") && strings.Contains(script, "ngModule") {
		scores[Angular] += 0.6
	}

	// Svelte detection
	if strings.Contains(script, "svelte") || strings.Contains(script, "SvelteComponent") {
		scores[Svelte] += 0.7
	}

	// Next.js detection
	if strings.Contains(script, "next/") || strings.Contains(script, "_N_E") {
		scores[NextJS] += 0.7
		scores[React] += 0.4 // Next.js is based on React
	}

	// Nuxt.js detection
	if strings.Contains(script, "nuxt") || strings.Contains(script, "$nuxt") {
		scores[NuxtJS] += 0.7
		scores[Vue] += 0.4 // Nuxt.js is based on Vue
	}

	// Gatsby detection
	if strings.Contains(script, "gatsby") || strings.Contains(script, "useStaticQuery") {
		scores[Gatsby] += 0.7
		scores[React] += 0.4 // Gatsby is based on React
	}

	// Remix detection
	if strings.Contains(script, "remix") || strings.Contains(script, "useLoaderData") {
		scores[Remix] += 0.7
		scores[React] += 0.4 // Remix is based on React
	}

	// SolidJS detection
	if strings.Contains(script, "solid-js") || strings.Contains(script, "createSignal") {
		scores[SolidJS] += 0.7
	}

	// Qwik detection
	if strings.Contains(script, "qwik") || strings.Contains(script, "component$") {
		scores[Qwik] += 0.7
	}
}

// detectVersion attempts to detect the framework version
func (d *Detector) detectVersion(framework FrameworkType, target *models.Target) string {
	// Check in scripts
	for _, script := range target.Scripts {
		switch framework {
		case React:
			// Try to find React version in script
			reactVersionRegex := regexp.MustCompile(`React\.version\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]`)
			if match := reactVersionRegex.FindStringSubmatch(script); len(match) > 1 {
				return match[1]
			}

			// Also check for version in import/require statements
			reactImportRegex := regexp.MustCompile(`react(-dom)?@([0-9]+\.[0-9]+\.[0-9]+)`)
			if match := reactImportRegex.FindStringSubmatch(script); len(match) > 2 {
				return match[2]
			}
		case Vue:
			// Try to find Vue version in script
			vueVersionRegex := regexp.MustCompile(`Vue\.version\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]`)
			if match := vueVersionRegex.FindStringSubmatch(script); len(match) > 1 {
				return match[1]
			}

			// Also check for version in import/require statements
			vueImportRegex := regexp.MustCompile(`vue@([0-9]+\.[0-9]+\.[0-9]+)`)
			if match := vueImportRegex.FindStringSubmatch(script); len(match) > 1 {
				return match[1]
			}
		case Angular:
			// Try to find Angular version in script
			angularVersionRegex := regexp.MustCompile(`VERSION\.full\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]`)
			if match := angularVersionRegex.FindStringSubmatch(script); len(match) > 1 {
				return match[1]
			}

			// Also check for version in import/require statements
			angularImportRegex := regexp.MustCompile(`angular[^@]*@([0-9]+\.[0-9]+\.[0-9]+)`)
			if match := angularImportRegex.FindStringSubmatch(script); len(match) > 1 {
				return match[1]
			}
		}
	}

	return ""
}

// isMetaFramework checks if the framework is a meta-framework
func (d *Detector) isMetaFramework(framework FrameworkType) bool {
	metaFrameworks := map[FrameworkType]bool{
		NextJS: true,
		NuxtJS: true,
		Gatsby: true,
		Remix:  true,
	}

	return metaFrameworks[framework]
}
