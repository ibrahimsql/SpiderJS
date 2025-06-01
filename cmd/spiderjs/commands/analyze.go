package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/analyzer"
	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/spf13/cobra"
)

// NewAnalyzeCommand creates the analyze command
func NewAnalyzeCommand(log *logger.Logger) *cobra.Command {
	var filePath string
	var outputFile string
	var format string
	var verbose bool
	var includeSourceMap bool
	var extractDependencies bool
	var checkVulnerabilities bool
	var detectFrameworks bool
	var timeout int

	analyzeCmd := &cobra.Command{
		Use:   "analyze [file]",
		Short: "Analyze a JavaScript file for vulnerabilities",
		Long: `Analyze a JavaScript file or directory for vulnerabilities and insights.
		
This command analyzes JavaScript files to detect frameworks, dependencies, and potential security issues.

Examples:
  spiderjs analyze app.js
  spiderjs analyze ./src --output report.json --format json
  spiderjs analyze bundle.js --extract-dependencies --check-vulnerabilities`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get file path from args or flag
			if len(args) > 0 {
				filePath = args[0]
			}

			// Validate file path
			if filePath == "" {
				return errors.New("file path is required")
			}

			// Check if file exists
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				return fmt.Errorf("failed to access file: %w", err)
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer cancel()

			// Create configuration
			cfg := &config.Config{
				Timeout: time.Duration(timeout) * time.Second,
				Output:  outputFile,
				Format:  format,
				AnalyzerOptions: config.AnalyzerOptions{
					IncludeSourceMap:     includeSourceMap,
					ExtractDependencies:  extractDependencies,
					CheckVulnerabilities: checkVulnerabilities,
					DetectFrameworks:     detectFrameworks,
					Verbose:              verbose,
				},
			}

			// Create analyzer
			a, err := analyzer.NewAnalyzer(ctx, cfg, log)
			if err != nil {
				return fmt.Errorf("failed to create analyzer: %w", err)
			}

			startTime := time.Now()

			// Handle directory or file
			var results []*models.AnalysisResult
			if fileInfo.IsDir() {
				// Walk directory and analyze all JS files
				log.Info("Analyzing directory", "path", filePath)

				err = filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}

					// Skip directories and non-JS files
					if info.IsDir() || !isJavaScriptFile(path) {
						return nil
					}

					// Create target
					target, err := models.NewTarget(path)
					if err != nil {
						log.Warn("Failed to create target", "path", path, "error", err)
						return nil
					}

					// Analyze file
					result, err := a.Analyze(ctx, target)
					if err != nil {
						log.Warn("Failed to analyze file", "path", path, "error", err)
						return nil
					}

					results = append(results, result)
					return nil
				})

				if err != nil {
					return fmt.Errorf("failed to walk directory: %w", err)
				}

				log.Success("Directory analysis completed", "files_analyzed", len(results))
			} else {
				// Analyze single file
				log.Info("Analyzing file", "path", filePath)

				// Create target
				target, err := models.NewTarget(filePath)
				if err != nil {
					return fmt.Errorf("failed to create target: %w", err)
				}

				// Analyze file
				result, err := a.Analyze(ctx, target)
				if err != nil {
					return fmt.Errorf("failed to analyze file: %w", err)
				}

				results = append(results, result)
				log.Success("File analysis completed")
			}

			duration := time.Since(startTime)

			// Print summary
			totalDeps := 0
			totalVulns := 0
			totalFrameworks := 0

			for _, result := range results {
				totalDeps += len(result.Dependencies)
				totalVulns += len(result.Vulnerabilities)
				if result.Frameworks != nil {
					totalFrameworks += len(result.Frameworks)
				}
			}

			log.Info("Analysis summary",
				"files", len(results),
				"duration", duration.String(),
				"dependencies", totalDeps,
				"vulnerabilities", totalVulns,
				"frameworks", totalFrameworks,
			)

			// Print detailed results if verbose
			if verbose {
				for _, result := range results {
					log.Info("File details", "path", result.Target.URL)

					if len(result.Dependencies) > 0 {
						log.Info("Dependencies found:")
						for i, dep := range result.Dependencies {
							log.Info(fmt.Sprintf("[%d] %s", i+1, dep.Name), "version", dep.Version)
						}
					}

					if len(result.Vulnerabilities) > 0 {
						log.Info("Vulnerabilities found:")
						for i, vuln := range result.Vulnerabilities {
							log.Info(fmt.Sprintf("[%d] %s", i+1, vuln.Type),
								"severity", vuln.Severity,
								"location", vuln.Location,
							)
						}
					}

					if result.Frameworks != nil && len(result.Frameworks) > 0 {
						log.Info("Frameworks detected:")
						for i, fw := range result.Frameworks {
							log.Info(fmt.Sprintf("[%d] %s", i+1, fw.Name), "version", fw.Version)
						}
					}

					if result.IsMinified {
						log.Info("File is minified")
					}

					if result.BundleType != "" {
						log.Info("Bundle type detected", "type", result.BundleType)
					}
				}
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
	analyzeCmd.Flags().StringVarP(&filePath, "file", "f", "", "file or directory to analyze")
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path")
	analyzeCmd.Flags().StringVar(&format, "format", "console", "output format (console, json, html, xml)")
	analyzeCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	analyzeCmd.Flags().BoolVar(&includeSourceMap, "include-source-map", false, "include source map in analysis")
	analyzeCmd.Flags().BoolVarP(&extractDependencies, "extract-dependencies", "d", true, "extract dependencies from the code")
	analyzeCmd.Flags().BoolVarP(&checkVulnerabilities, "check-vulnerabilities", "c", true, "check for vulnerabilities")
	analyzeCmd.Flags().BoolVarP(&detectFrameworks, "detect-frameworks", "r", true, "detect frameworks used")
	analyzeCmd.Flags().IntVarP(&timeout, "timeout", "t", 60, "analysis timeout in seconds")

	return analyzeCmd
}

// isJavaScriptFile checks if a file is a JavaScript file based on its extension
func isJavaScriptFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".js" || ext == ".jsx" || ext == ".mjs" || ext == ".cjs" || ext == ".ts" || ext == ".tsx"
}
