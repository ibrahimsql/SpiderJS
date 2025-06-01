package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	v1 "github.com/ibrahimsql/spiderjs/api/v1"
	bundleanalyzer "github.com/ibrahimsql/spiderjs/internal/analyzer/bundle"
	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/ml"
	"github.com/ibrahimsql/spiderjs/internal/scanner"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/version"
)

// Server represents the SpiderJS web server
type Server struct {
	config   *config.Config
	log      *logger.Logger
	server   *http.Server
	handlers map[string]http.HandlerFunc
}

// NewServer creates a new web server
func NewServer(cfg *config.Config, log *logger.Logger) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	s := &Server{
		config:   cfg,
		log:      log,
		handlers: make(map[string]http.HandlerFunc),
	}

	// Register handlers
	s.registerHandlers()

	return s, nil
}

// Start starts the web server
func (s *Server) Start(ctx context.Context, host string, port int) error {
	if ctx.Err() != nil {
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	s.log.Success("Starting web server on %s", addr)

	// Create router
	mux := http.NewServeMux()

	// Register handlers
	for path, handler := range s.handlers {
		mux.HandleFunc(path, handler)
	}

	// Create server
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Errorf("Error starting server: %v", err)
		}
	}()

	s.log.Success("Server started successfully")

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown server
	return s.Shutdown()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	s.log.Success("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown server
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	s.log.Success("Server stopped gracefully")
	return nil
}

// registerHandlers registers all HTTP handlers
func (s *Server) registerHandlers() {
	s.handlers["/"] = s.handleIndex()
	s.handlers["/api/version"] = s.handleVersion()
	s.handlers["/api/scan"] = s.handleScan()
	s.handlers["/api/config"] = s.handleConfig()
	s.handlers["/api/health"] = s.handleHealth()
	s.handlers["/api/ml/predict"] = s.handleMLPredict()
}

// handleIndex handles the index page
func (s *Server) handleIndex() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<!DOCTYPE html>
			<html>
			<head>
				<title>SpiderJS</title>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<style>
					body {
						font-family: Arial, sans-serif;
						max-width: 800px;
						margin: 0 auto;
						padding: 20px;
						line-height: 1.6;
					}
					h1 {
						color: #333;
						border-bottom: 1px solid #eee;
						padding-bottom: 10px;
					}
					.info {
						background-color: #f8f9fa;
						border-left: 4px solid #5bc0de;
						padding: 15px;
						margin-bottom: 20px;
					}
					.footer {
						margin-top: 40px;
						font-size: 0.8em;
						color: #777;
						text-align: center;
					}
				</style>
			</head>
			<body>
				<h1>SpiderJS Web Server</h1>
				<div class="info">
					<p>SpiderJS is a powerful tool for analyzing and scanning modern JavaScript applications.</p>
					<p>This web server provides a user interface for SpiderJS.</p>
				</div>
				<h2>API Endpoints</h2>
				<ul>
					<li><a href="/api/version">/api/version</a> - Get version information</li>
					<li><a href="/api/health">/api/health</a> - Check server health</li>
					<li>/api/scan - Scan a target (POST)</li>
					<li>/api/config - Get or update configuration (GET/POST)</li>
				</ul>
				<div class="footer">
					<p>SpiderJS v%s</p>
				</div>
			</body>
			</html>
		`, version.GetVersion())
	}
}

// handleVersion handles the version endpoint
func (s *Server) handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Set JSON content type
		w.Header().Set("Content-Type", "application/json")

		// Get version info
		versionInfo := version.GetInfo()

		// Return JSON response
		if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
			s.log.Errorf("Failed to encode version info: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// handleScan handles the scan endpoint
func (s *Server) handleScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request body
		var req struct {
			URL string `json:"url"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if req.URL == "" {
			http.Error(w, "URL is required", http.StatusBadRequest)
			return
		}

		// Create configuration
		cfg := config.LoadDefaultConfig()
		cfg.URL = req.URL

		// Create scanner
		scanner, err := scanner.NewScanner(r.Context(), cfg, s.log)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create scanner: %v", err), http.StatusInternalServerError)
			return
		}

		// Perform scan
		result, err := scanner.Scan(r.Context())
		if err != nil {
			s.log.Errorf("Error handling scan request: %v", err)
			http.Error(w, fmt.Sprintf("Error handling scan request: %v", err), http.StatusInternalServerError)
			return
		}

		// Return result
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// handleConfig handles the configuration endpoint
func (s *Server) handleConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Return current configuration
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.config)

		case http.MethodPost:
			// Update configuration
			var cfg config.Config
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, fmt.Sprintf("Invalid configuration: %v", err), http.StatusBadRequest)
				return
			}

			// Validate configuration
			if err := cfg.Validate(); err != nil {
				http.Error(w, fmt.Sprintf("Invalid configuration: %v", err), http.StatusBadRequest)
				return
			}

			// Update configuration
			s.config = &cfg

			// Return updated configuration
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.config)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleHealth handles the health endpoint
func (s *Server) handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Create response
		resp := struct {
			Status    string    `json:"status"`
			Timestamp time.Time `json:"timestamp"`
			Version   string    `json:"version"`
		}{
			Status:    "ok",
			Timestamp: time.Now(),
			Version:   version.GetVersion(),
		}

		// Set JSON content type
		w.Header().Set("Content-Type", "application/json")

		// Return JSON response
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.log.Errorf("Failed to encode health response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// handleMLPredict handles the ML prediction endpoint
func (s *Server) handleMLPredict() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request body
		var req struct {
			Code      string  `json:"code"`
			Threshold float64 `json:"threshold,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		if req.Code == "" {
			http.Error(w, "Code is required", http.StatusBadRequest)
			return
		}

		// Import ML package
		mlPredictor, err := ml.NewPredictor(s.log)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create predictor: %v", err), http.StatusInternalServerError)
			return
		}

		// Set threshold if provided
		if req.Threshold > 0 {
			mlPredictor.SetThreshold(req.Threshold)
		}

		// Initialize predictor
		if err := mlPredictor.Initialize(r.Context()); err != nil {
			http.Error(w, fmt.Sprintf("Failed to initialize predictor: %v", err), http.StatusInternalServerError)
			return
		}

		// Predict vulnerabilities
		results, err := mlPredictor.PredictFromCode(r.Context(), req.Code)
		if err != nil {
			s.log.Errorf("Error handling analyze request: %v", err)
			http.Error(w, fmt.Sprintf("Error handling analyze request: %v", err), http.StatusInternalServerError)
			return
		}

		// Return response
		w.Header().Set("Content-Type", "application/json")
		resp := struct {
			Results []*ml.PredictionResult `json:"results"`
		}{
			Results: results,
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.log.Errorf("Failed to encode response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
}

// setupRouter sets up the HTTP router
func (s *Server) setupRouter() *mux.Router {
	r := mux.NewRouter()

	// Register the v1 API routes
	analyzer, err := bundleanalyzer.NewAnalyzer(s.log)
	if err != nil {
		s.log.Errorf("Failed to create bundle analyzer: %v", err)
	}

	predictor, err := ml.NewPredictor(s.log)
	if err != nil {
		s.log.Errorf("Failed to create ML predictor: %v", err)
	}

	scanner, err := scanner.NewScanner(context.Background(), s.config, s.log)
	if err != nil {
		s.log.Errorf("Failed to create scanner: %v", err)
	}

	v1Handler := v1.NewHandler(scanner, analyzer, predictor)
	v1.RegisterV1Routes(r, v1Handler)

	return r
}
