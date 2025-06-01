package helpers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gorilla/mux"
)

// MockServer represents a mock HTTP server for testing
type MockServer struct {
	Server *httptest.Server
	Router *mux.Router
}

// NewMockServer creates a new mock server with the given router
func NewMockServer() *MockServer {
	router := mux.NewRouter()
	server := httptest.NewServer(router)

	return &MockServer{
		Server: server,
		Router: router,
	}
}

// Close closes the mock server
func (m *MockServer) Close() {
	m.Server.Close()
}

// SetupDefaultRoutes sets up default routes for testing
func (m *MockServer) SetupDefaultRoutes() {
	// Health endpoint
	m.Router.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"status":  "ok",
			"version": "1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Version endpoint
	m.Router.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"version":   "1.0.0",
			"gitCommit": "abcdef123456",
			"goVersion": "go1.21.0",
			"buildDate": time.Now().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Scan endpoint
	m.Router.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"id":     "scan_123456789",
			"status": "running",
			"url":    "https://example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Scan status endpoint
	m.Router.HandleFunc("/api/v1/scan/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		response := map[string]interface{}{
			"id":       vars["id"],
			"status":   "completed",
			"progress": 100,
			"url":      "https://example.com",
			"result": map[string]interface{}{
				"vulnerabilities": []interface{}{
					map[string]string{
						"id":          "vuln-001",
						"type":        "xss",
						"severity":    "high",
						"description": "Cross-site scripting vulnerability",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Analyze endpoint
	m.Router.HandleFunc("/api/v1/analyze", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"id":         "analyze_123456789",
			"url":        "https://example.com/bundle.js",
			"bundleType": "webpack",
			"isMinified": true,
			"size":       1024567,
			"dependencies": []interface{}{
				map[string]string{
					"name":    "react",
					"version": "17.0.2",
				},
				map[string]string{
					"name":    "react-dom",
					"version": "17.0.2",
				},
			},
			"frameworks": []string{"react", "redux"},
			"vulnerabilities": []interface{}{
				map[string]string{
					"id":          "vuln-001",
					"type":        "eval",
					"severity":    "high",
					"description": "Dangerous eval usage",
					"location":    "bundle.js:123",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// JavaScript bundle endpoint
	m.Router.HandleFunc("/bundle.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(GetWebpackScript()))
	}).Methods("GET")

	// Example API endpoint
	m.Router.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"message": "Hello from API",
			"data": []interface{}{
				map[string]interface{}{"id": 1, "name": "Item 1"},
				map[string]interface{}{"id": 2, "name": "Item 2"},
				map[string]interface{}{"id": 3, "name": "Item 3"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")
}
