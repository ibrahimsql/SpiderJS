package commands

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/scanner"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/spf13/cobra"
)

// NewScanCommand creates the scan command
func NewScanCommand(log *logger.Logger) *cobra.Command {
	var targetURL string
	var timeout int
	var maxDepth int
	var concurrent int
	var outputFile string
	var format string
	var profile string
	var includeXSS bool
	var includeInjection bool
	var includeCSRF bool
	var includeCORS bool
	var includeHeaders bool
	var includeCookies bool
	var includeSupplyChain bool
	var includePrototype bool
	var includeSubdomains bool
	var activeScan bool
	var fuzzLevel int

	scanCmd := &cobra.Command{
		Use:   "scan [url]",
		Short: "Scan a JavaScript application for vulnerabilities",
		Long: `Scan a JavaScript application for vulnerabilities.
		
This command crawls a web application, extracts JavaScript files, and analyzes them for security vulnerabilities.

Examples:
  spiderjs scan https://example.com
  spiderjs scan https://example.com --max-depth 3 --timeout 60
  spiderjs scan https://example.com --output report.json --format json
  spiderjs scan https://example.com --profile comprehensive
  spiderjs scan https://example.com --include-xss --include-injection`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get URL from args or flag
			if len(args) > 0 {
				targetURL = args[0]
			}

			// Validate URL
			if targetURL == "" {
				return errors.New("URL is required")
			}

			parsedURL, err := url.Parse(targetURL)
			if err != nil {
				return fmt.Errorf("invalid URL: %w", err)
			}

			if parsedURL.Scheme == "" {
				parsedURL.Scheme = "https"
				targetURL = parsedURL.String()
			}

			// Load profile if specified
			if profile != "" {
				log.Info("Loading scan profile", "profile", profile)
				// TODO: Load profile from configs/profiles/
			}

			// Create scan configuration
			scanCfg := &config.Config{
				URL:        targetURL,
				Timeout:    time.Duration(timeout) * time.Second,
				MaxDepth:   maxDepth,
				Concurrent: concurrent,
				Output:     outputFile,
				Format:     format,
			}

			// Set scan options
			scanCfg.ScanOptions = config.ScanOptions{
				IncludeXSS:         includeXSS,
				IncludeInjection:   includeInjection,
				IncludeCSRF:        includeCSRF,
				IncludeCORS:        includeCORS,
				IncludeHeaders:     includeHeaders,
				IncludeCookies:     includeCookies,
				IncludeSupplyChain: includeSupplyChain,
				IncludePrototype:   includePrototype,
				IncludeSubdomains:  includeSubdomains,
				ActiveScan:         activeScan,
				FuzzLevel:          fuzzLevel,
			}

			// Validate configuration
			if err := scanCfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}

			// Set defaults
			scanCfg.SetDefaults()

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), scanCfg.Timeout)
			defer cancel()

			// Create scanner
			s, err := scanner.NewScanner(ctx, scanCfg, log)
			if err != nil {
				return fmt.Errorf("failed to create scanner: %w", err)
			}

			// Print scan info
			log.Info("Starting scan", "url", targetURL, "max_depth", maxDepth, "timeout", timeout)

			// Run scan
			startTime := time.Now()
			result, err := s.Scan(ctx)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			duration := time.Since(startTime)

			// Print summary
			log.Success("Scan completed successfully", "duration", duration.String())
			log.Info("Scan summary",
				"url", targetURL,
				"duration", duration.String(),
				"findings", len(result.Findings),
			)

			// Print findings
			if len(result.Findings) > 0 {
				log.Info("Issues found:")
				for i, finding := range result.Findings {
					log.Info(fmt.Sprintf("[%d] %s", i+1, finding.Title),
						"type", finding.Type,
						"severity", finding.Severity,
						"description", finding.Description,
					)
				}
			} else {
				log.Info("No vulnerabilities found")
			}

			// Save report
			if outputFile != "" {
				// TODO: Save report to file
				log.Info("Report saved", "path", outputFile)
			}

			return nil
		},
	}

	// Add flags
	scanCmd.Flags().StringVarP(&targetURL, "url", "u", "", "target URL to scan")
	scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 300, "scan timeout in seconds")
	scanCmd.Flags().IntVarP(&maxDepth, "max-depth", "d", 3, "maximum crawl depth")
	scanCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 10, "number of concurrent workers")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	scanCmd.Flags().StringVarP(&format, "format", "f", "console", "output format (console, json, html, xml)")
	scanCmd.Flags().StringVarP(&profile, "profile", "p", "", "scan profile (quick, standard, comprehensive)")

	// Vulnerability flags
	scanCmd.Flags().BoolVar(&includeXSS, "include-xss", true, "scan for XSS vulnerabilities")
	scanCmd.Flags().BoolVar(&includeInjection, "include-injection", true, "scan for injection vulnerabilities")
	scanCmd.Flags().BoolVar(&includeCSRF, "include-csrf", true, "scan for CSRF vulnerabilities")
	scanCmd.Flags().BoolVar(&includeCORS, "include-cors", true, "scan for CORS misconfigurations")
	scanCmd.Flags().BoolVar(&includeHeaders, "include-headers", true, "scan for security header issues")
	scanCmd.Flags().BoolVar(&includeCookies, "include-cookies", true, "scan for cookie issues")
	scanCmd.Flags().BoolVar(&includeSupplyChain, "include-supply-chain", true, "scan for supply chain vulnerabilities")
	scanCmd.Flags().BoolVar(&includePrototype, "include-prototype", true, "scan for prototype pollution")
	scanCmd.Flags().BoolVar(&includeSubdomains, "include-subdomains", false, "include subdomains in scan")
	scanCmd.Flags().BoolVar(&activeScan, "active", false, "perform active scanning (potentially intrusive)")
	scanCmd.Flags().IntVar(&fuzzLevel, "fuzz-level", 1, "fuzzing level (0-3)")

	return scanCmd
}
