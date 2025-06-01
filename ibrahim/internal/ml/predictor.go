package ml

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// FeatureVector represents a feature vector for ML prediction
type FeatureVector []float64

// PredictionResult represents the result of a vulnerability prediction
type PredictionResult struct {
	VulnerabilityType string  `json:"vulnerability_type"`
	Probability       float64 `json:"probability"`
	Confidence        float64 `json:"confidence"`
	Evidence          string  `json:"evidence,omitempty"`
}

// Predictor is a machine learning-based vulnerability predictor
type Predictor struct {
	log           *logger.Logger
	modelPath     string
	featureNames  []string
	weights       []FeatureVector
	biases        []float64
	classNames    []string
	threshold     float64
	isInitialized bool
}

// NewPredictor creates a new vulnerability predictor
func NewPredictor(log *logger.Logger) (*Predictor, error) {
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}

	return &Predictor{
		log:           log,
		modelPath:     "configs/ml/model.json",
		threshold:     0.7,
		isInitialized: false,
	}, nil
}

// Initialize loads the ML model
func (p *Predictor) Initialize(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	// Check if model file exists
	if _, err := os.Stat(p.modelPath); os.IsNotExist(err) {
		p.log.Warning("ML model file not found at %s, using default model", p.modelPath)
		// Use default model (simplified for demonstration)
		p.initializeDefaultModel()
		return nil
	}

	// In a real implementation, we would load model weights from a file
	// For demonstration, we'll use a simplified model
	p.initializeDefaultModel()
	p.isInitialized = true

	p.log.Success("ML predictor initialized successfully")
	return nil
}

// initializeDefaultModel initializes a default model for demonstration
func (p *Predictor) initializeDefaultModel() {
	// Feature names (simplified)
	p.featureNames = []string{
		"has_user_input",
		"uses_eval",
		"uses_innerhtml",
		"uses_document_write",
		"uses_fetch_api",
		"has_jwt",
		"has_cors_headers",
		"has_csp_headers",
		"has_prototype_manipulation",
		"has_event_handlers",
	}

	// Class names (vulnerability types)
	p.classNames = []string{
		"xss",
		"injection",
		"csrf",
		"prototype_pollution",
		"jwt_vulnerability",
	}

	// Simplified weights (in a real model, these would be learned)
	p.weights = []FeatureVector{
		// XSS weights
		{0.8, 0.7, 0.9, 0.9, 0.3, 0.1, -0.5, -0.7, 0.2, 0.6},
		// Injection weights
		{0.7, 0.8, 0.3, 0.4, 0.6, 0.2, 0.1, -0.3, 0.3, 0.2},
		// CSRF weights
		{0.5, 0.2, 0.3, 0.3, 0.7, 0.4, -0.2, -0.3, 0.1, 0.4},
		// Prototype pollution weights
		{0.3, 0.4, 0.2, 0.2, 0.1, 0.1, 0.0, -0.1, 0.9, 0.3},
		// JWT vulnerability weights
		{0.2, 0.3, 0.1, 0.1, 0.5, 0.9, 0.1, -0.2, 0.1, 0.2},
	}

	// Biases
	p.biases = []float64{-0.5, -0.4, -0.3, -0.4, -0.5}
}

// ExtractFeatures extracts features from a target
func (p *Predictor) ExtractFeatures(target *models.Target) (FeatureVector, error) {
	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	// Initialize feature vector
	features := make(FeatureVector, len(p.featureNames))

	// Extract features from scripts
	for _, script := range target.Scripts {
		// Check for user input handling
		if strings.Contains(script, "getElementById") || strings.Contains(script, "querySelector") {
			features[0] = 1.0
		}

		// Check for eval usage
		if strings.Contains(script, "eval(") || strings.Contains(script, "new Function(") {
			features[1] = 1.0
		}

		// Check for innerHTML
		if strings.Contains(script, "innerHTML") || strings.Contains(script, "outerHTML") {
			features[2] = 1.0
		}

		// Check for document.write
		if strings.Contains(script, "document.write") {
			features[3] = 1.0
		}

		// Check for fetch API
		if strings.Contains(script, "fetch(") || strings.Contains(script, "XMLHttpRequest") {
			features[4] = 1.0
		}

		// Check for JWT
		if strings.Contains(script, "jwt") || strings.Contains(script, "Bearer ") {
			features[5] = 1.0
		}

		// Check for prototype manipulation
		if strings.Contains(script, "prototype") && (strings.Contains(script, "Object.") || strings.Contains(script, ".__proto__")) {
			features[8] = 1.0
		}

		// Check for event handlers
		if strings.Contains(script, "addEventListener") || strings.Contains(script, "onclick") {
			features[9] = 1.0
		}
	}

	// Extract features from headers
	if target.Headers != nil {
		// Check for CORS headers
		if _, ok := target.Headers["Access-Control-Allow-Origin"]; ok {
			features[6] = 1.0
		}

		// Check for CSP headers
		if _, ok := target.Headers["Content-Security-Policy"]; ok {
			features[7] = 1.0
		}
	}

	return features, nil
}

// Predict predicts vulnerabilities in a target
func (p *Predictor) Predict(ctx context.Context, target *models.Target) ([]*PredictionResult, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if !p.isInitialized {
		if err := p.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("failed to initialize predictor: %w", err)
		}
	}

	if target == nil {
		return nil, errors.New("target cannot be nil")
	}

	// Extract features
	features, err := p.ExtractFeatures(target)
	if err != nil {
		return nil, fmt.Errorf("failed to extract features: %w", err)
	}

	// Make predictions
	var results []*PredictionResult

	for i, className := range p.classNames {
		// Calculate logit (dot product of features and weights + bias)
		logit := p.biases[i]
		for j, feature := range features {
			logit += feature * p.weights[i][j]
		}

		// Apply sigmoid to get probability
		probability := sigmoid(logit)

		// If probability is above threshold, add to results
		if probability >= p.threshold {
			result := &PredictionResult{
				VulnerabilityType: className,
				Probability:       probability,
				Confidence:        calculateConfidence(probability),
			}

			// Add evidence based on the vulnerability type
			switch className {
			case "xss":
				if features[2] > 0 {
					result.Evidence = "Uses innerHTML which can lead to XSS"
				} else if features[3] > 0 {
					result.Evidence = "Uses document.write which can lead to XSS"
				}
			case "injection":
				if features[1] > 0 {
					result.Evidence = "Uses eval which can lead to code injection"
				}
			case "prototype_pollution":
				if features[8] > 0 {
					result.Evidence = "Manipulates prototypes which can lead to prototype pollution"
				}
			case "jwt_vulnerability":
				if features[5] > 0 {
					result.Evidence = "Uses JWT which may have vulnerabilities if not properly implemented"
				}
			}

			results = append(results, result)
		}
	}

	// Sort results by probability (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results, nil
}

// PredictFromCode predicts vulnerabilities from code
func (p *Predictor) PredictFromCode(ctx context.Context, code string) ([]*PredictionResult, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	if !p.isInitialized {
		if err := p.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("failed to initialize predictor: %w", err)
		}
	}

	if code == "" {
		return nil, errors.New("code cannot be empty")
	}

	// Create a temporary target with the code as a script
	target := &models.Target{
		Scripts: []string{code},
	}

	return p.Predict(ctx, target)
}

// sigmoid calculates the sigmoid function
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// calculateConfidence calculates the confidence score
func calculateConfidence(probability float64) float64 {
	// Simple linear transformation to get confidence
	// 0.5 -> 0.0, 1.0 -> 1.0
	if probability <= 0.5 {
		return 0.0
	}
	return (probability - 0.5) * 2.0
}

// SetModelPath sets the path to the ML model
func (p *Predictor) SetModelPath(path string) {
	p.modelPath = path
	p.isInitialized = false
}

// SetThreshold sets the prediction threshold
func (p *Predictor) SetThreshold(threshold float64) {
	if threshold < 0.0 || threshold > 1.0 {
		p.log.Warning("Threshold must be between 0.0 and 1.0, using default")
		return
	}
	p.threshold = threshold
}

// GetFeatureNames returns the feature names
func (p *Predictor) GetFeatureNames() []string {
	return p.featureNames
}

// GetClassNames returns the class names
func (p *Predictor) GetClassNames() []string {
	return p.classNames
}
