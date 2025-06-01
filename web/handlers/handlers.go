package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/analyzer"
	"github.com/ibrahimsql/spiderjs/pkg/models"
)

// WebHandler handles the web UI requests
type WebHandler struct {
	log         *logger.Logger
	config      *config.Config
	analyzer    *analyzer.BundleAnalyzer
	templates   map[string]*template.Template
	templateDir string
}

// NewWebHandler creates a new WebHandler
func NewWebHandler(
	log *logger.Logger,
	config *config.Config,
	analyzer *analyzer.BundleAnalyzer,
) *WebHandler {
	return &WebHandler{
		log:         log,
		config:      config,
		analyzer:    analyzer,
		templates:   make(map[string]*template.Template),
		templateDir: config.Web.TemplateDir,
	}
}

// Initialize loads and parses all templates
func (h *WebHandler) Initialize() error {
	h.log.Info("Initializing web handlers")

	// Define template files
	templates := []string{
		"index.html",
		"analyze.html",
		"scan.html",
	}

	// Load all templates
	for _, tmpl := range templates {
		path := filepath.Join(h.templateDir, tmpl)
		h.log.Debug("Loading template", "path", path)

		t, err := template.ParseFiles(path)
		if err != nil {
			h.log.Error("Failed to parse template", "path", path, "error", err)
			return err
		}

		h.templates[tmpl] = t
	}

	return nil
}

// Home handles the home page request
func (h *WebHandler) Home(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Handling home page request")

	// Render template
	tmpl, ok := h.templates["index.html"]
	if !ok {
		h.log.Error("Template not found", "template", "index.html")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "SpiderJS - JavaScript Code Analysis Tool",
	}

	if err := tmpl.Execute(w, data); err != nil {
		h.log.Error("Failed to execute template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// Analyze handles the analyze page request
func (h *WebHandler) Analyze(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Handling analyze page request")

	// Render template
	tmpl, ok := h.templates["analyze.html"]
	if !ok {
		h.log.Error("Template not found", "template", "analyze.html")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "SpiderJS - Analyze JavaScript",
	}

	if err := tmpl.Execute(w, data); err != nil {
		h.log.Error("Failed to execute template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// Scan handles the scan page request
func (h *WebHandler) Scan(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Handling scan page request")

	// Render template
	tmpl, ok := h.templates["scan.html"]
	if !ok {
		h.log.Error("Template not found", "template", "scan.html")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "SpiderJS - Scan Website",
	}

	if err := tmpl.Execute(w, data); err != nil {
		h.log.Error("Failed to execute template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// AnalyzeScript handles the script analysis request
func (h *WebHandler) AnalyzeScript(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Handling script analysis request")

	// Only allow POST requests
	if r.Method != http.MethodPost {
		h.log.Warn("Invalid request method", "method", r.Method)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.log.Error("Failed to parse form", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Get script content
	script := r.FormValue("script")
	if script == "" {
		h.log.Warn("Empty script content")
		http.Error(w, "Bad Request: Script content is required", http.StatusBadRequest)
		return
	}

	// Create target
	target, err := models.NewTarget("direct-input")
	if err != nil {
		h.log.Error("Failed to create target", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	target.Scripts = []string{script}

	// Analyze script
	result, err := h.analyzer.Analyze(r.Context(), target)
	if err != nil {
		h.log.Error("Failed to analyze script", "error", err)
		http.Error(w, "Analysis Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Encode and send response
	if err := json.NewEncoder(w).Encode(result); err != nil {
		h.log.Error("Failed to encode response", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// ScanWebsite handles the website scanning request
func (h *WebHandler) ScanWebsite(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Handling website scan request")

	// Only allow POST requests
	if r.Method != http.MethodPost {
		h.log.Warn("Invalid request method", "method", r.Method)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.log.Error("Failed to parse form", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Get URL
	url := r.FormValue("url")
	if url == "" {
		h.log.Warn("Empty URL")
		http.Error(w, "Bad Request: URL is required", http.StatusBadRequest)
		return
	}

	// Create scanner
	scanner := NewScanner(h.log, h.config, h.analyzer)

	// Scan website
	result, err := scanner.Scan(r.Context(), url)
	if err != nil {
		h.log.Error("Failed to scan website", "url", url, "error", err)
		http.Error(w, "Scan Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Encode and send response
	if err := json.NewEncoder(w).Encode(result); err != nil {
		h.log.Error("Failed to encode response", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// RegisterRoutes registers the handler routes
func (h *WebHandler) RegisterRoutes(mux *http.ServeMux) {
	// Static files
	fileServer := http.FileServer(http.Dir(h.config.Web.StaticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// Web pages
	mux.HandleFunc("/", h.Home)
	mux.HandleFunc("/analyze", h.Analyze)
	mux.HandleFunc("/scan", h.Scan)

	// API endpoints
	mux.HandleFunc("/api/analyze", h.AnalyzeScript)
	mux.HandleFunc("/api/scan", h.ScanWebsite)
}
