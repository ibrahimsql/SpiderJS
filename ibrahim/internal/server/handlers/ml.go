package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/ibrahimsql/spiderjs/internal/ml"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// MLHandler handles ML-related API endpoints
type MLHandler struct {
	log       *logger.Logger
	predictor *ml.Predictor
}

// NewMLHandler creates a new ML handler
func NewMLHandler(log *logger.Logger) (*MLHandler, error) {
	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	predictor, err := ml.NewPredictor(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create predictor: %w", err)
	}

	// Initialize the predictor
	if err := predictor.Initialize(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize predictor: %w", err)
	}

	return &MLHandler{
		log:       log,
		predictor: predictor,
	}, nil
}

// HandlePredict handles the /api/ml/predict endpoint
func (h *MLHandler) HandlePredict() http.HandlerFunc {
	type request struct {
		Code      string  `json:"code"`
		URL       string  `json:"url,omitempty"`
		Threshold float64 `json:"threshold,omitempty"`
	}

	type response struct {
		Results []*ml.PredictionResult `json:"results"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Parse request
		var req request
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
			return
		}

		// Validate request
		if req.Code == "" {
			http.Error(w, "Code is required", http.StatusBadRequest)
			return
		}

		// Set threshold if provided
		if req.Threshold > 0 {
			h.predictor.SetThreshold(req.Threshold)
		}

		// Predict vulnerabilities
		results, err := h.predictor.PredictFromCode(r.Context(), req.Code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to predict vulnerabilities: %v", err), http.StatusInternalServerError)
			return
		}

		// Create response
		resp := response{
			Results: results,
		}

		// Return response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			h.log.ErrorMsg("Failed to encode response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAnalyzeURL handles the /api/ml/analyze-url endpoint
func (h *MLHandler) HandleAnalyzeURL() http.HandlerFunc {
	type request struct {
		URL       string  `json:"url"`
		Threshold float64 `json:"threshold,omitempty"`
	}

	type response struct {
		Results []*ml.PredictionResult `json:"results"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Parse request
		var req request
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
			return
		}

		// Validate request
		if req.URL == "" {
			http.Error(w, "URL is required", http.StatusBadRequest)
			return
		}

		// Set threshold if provided
		if req.Threshold > 0 {
			h.predictor.SetThreshold(req.Threshold)
		}

		// Create target
		target := &models.Target{
			URL: "", // Will be set by the scanner
		}

		// Predict vulnerabilities
		results, err := h.predictor.Predict(r.Context(), target)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to predict vulnerabilities: %v", err), http.StatusInternalServerError)
			return
		}

		// Create response
		resp := response{
			Results: results,
		}

		// Return response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			h.log.ErrorMsg("Failed to encode response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// RegisterRoutes registers the ML handler routes
func (h *MLHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/ml/predict", h.HandlePredict())
	mux.HandleFunc("/api/ml/analyze-url", h.HandleAnalyzeURL())
}
