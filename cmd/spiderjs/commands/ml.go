package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ibrahimsql/spiderjs/internal/ml"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/spf13/cobra"
)

// NewMLCmd creates the ml command
func NewMLCmd(ctx context.Context, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ml [file|code]",
		Short: "Use machine learning to predict vulnerabilities",
		Long: `Use machine learning to predict vulnerabilities in JavaScript code.
This command can analyze a file or a string of code to identify potential security issues.`,
		Example: `  # Analyze a file
  spiderjs ml /path/to/file.js
  
  # Analyze code directly
  spiderjs ml --code "document.getElementById('user').innerHTML = input;"
  
  # Adjust prediction threshold
  spiderjs ml --threshold 0.8 /path/to/file.js`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse flags
			code, _ := cmd.Flags().GetString("code")
			threshold, _ := cmd.Flags().GetFloat64("threshold")
			outputFormat, _ := cmd.Flags().GetString("format")
			outputFile, _ := cmd.Flags().GetString("output")

			// Create predictor
			predictor, err := ml.NewPredictor(log)
			if err != nil {
				return fmt.Errorf("failed to create predictor: %w", err)
			}

			// Set threshold if provided
			if threshold > 0 {
				predictor.SetThreshold(threshold)
			}

			// Initialize predictor
			if err := predictor.Initialize(ctx); err != nil {
				return fmt.Errorf("failed to initialize predictor: %w", err)
			}

			var results []*ml.PredictionResult

			if code != "" {
				// Analyze code directly
				log.Success("Analyzing code with ML model")
				results, err = predictor.PredictFromCode(ctx, code)
				if err != nil {
					return fmt.Errorf("failed to predict from code: %w", err)
				}
			} else if len(args) > 0 {
				// Analyze file
				filePath := args[0]
				log.Success("Analyzing file %s with ML model", filePath)

				// Read file
				fileContent, err := ioutil.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read file: %w", err)
				}

				// Create target with file content
				target := &models.Target{
					Scripts: []string{string(fileContent)},
				}

				// Predict vulnerabilities
				results, err = predictor.Predict(ctx, target)
				if err != nil {
					return fmt.Errorf("failed to predict: %w", err)
				}
			} else {
				return fmt.Errorf("no input provided, use --code flag or provide a file path")
			}

			// Process results
			if len(results) == 0 {
				log.Success("No vulnerabilities detected")
				return nil
			}

			log.Success("Found %d potential vulnerabilities", len(results))

			// Output results
			switch strings.ToLower(outputFormat) {
			case "json":
				outputJSON(results, outputFile, log)
			default:
				outputText(results, outputFile, log)
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().String("code", "", "JavaScript code to analyze")
	cmd.Flags().Float64("threshold", 0.7, "prediction confidence threshold (0.0-1.0)")
	cmd.Flags().StringP("format", "f", "text", "output format (text, json)")
	cmd.Flags().StringP("output", "o", "", "output file path")

	return cmd
}

// outputJSON outputs results in JSON format
func outputJSON(results []*ml.PredictionResult, outputFile string, log *logger.Logger) {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.ErrorMsg("Failed to marshal results to JSON: %v", err)
		return
	}

	if outputFile == "" {
		// Output to stdout
		fmt.Println(string(jsonData))
	} else {
		// Output to file
		if err := writeToFile(outputFile, jsonData); err != nil {
			log.ErrorMsg("Failed to write to file: %v", err)
		} else {
			log.Success("Results written to %s", outputFile)
		}
	}
}

// outputText outputs results in text format
func outputText(results []*ml.PredictionResult, outputFile string, log *logger.Logger) {
	var output strings.Builder

	output.WriteString("Vulnerability Prediction Results:\n")
	output.WriteString("===============================\n\n")

	for i, result := range results {
		output.WriteString(fmt.Sprintf("Vulnerability #%d:\n", i+1))
		output.WriteString(fmt.Sprintf("  Type: %s\n", result.VulnerabilityType))
		output.WriteString(fmt.Sprintf("  Probability: %.2f\n", result.Probability))
		output.WriteString(fmt.Sprintf("  Confidence: %.2f\n", result.Confidence))
		if result.Evidence != "" {
			output.WriteString(fmt.Sprintf("  Evidence: %s\n", result.Evidence))
		}
		output.WriteString("\n")
	}

	if outputFile == "" {
		// Output to stdout
		fmt.Print(output.String())
	} else {
		// Output to file
		if err := writeToFile(outputFile, []byte(output.String())); err != nil {
			log.ErrorMsg("Failed to write to file: %v", err)
		} else {
			log.Success("Results written to %s", outputFile)
		}
	}
}

// writeToFile writes data to a file
func writeToFile(filePath string, data []byte) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Write to file
	return ioutil.WriteFile(filePath, data, 0644)
}
