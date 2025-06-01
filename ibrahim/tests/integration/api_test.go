package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	v1 "github.com/ibrahimsql/spiderjs/api/v1"
	"github.com/ibrahimsql/spiderjs/internal/analyzer/bundle"
	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/ml"
	"github.com/ibrahimsql/spiderjs/internal/scanner"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAPITestServer sets up a test server with API routes
func setupAPITestServer(t *testing.T) *httptest.Server {
	// Initialize logger
	log := logger.NewLogger()

	// Create config
	cfg := config.LoadDefaultConfig()

	// Create analyzer
	analyzer, err := bundle.NewAnalyzer(log)
	require.NoError(t, err)

	// Create predictor
	predictor, err := ml.NewPredictor(log)
	require.NoError(t, err)

	// Create scanner
	s, err := scanner.NewScanner(context.Background(), cfg, log)
	require.NoError(t, err)

	// Create API handler
	handler := v1.NewHandler(s, analyzer, predictor)

	// Create router
	router := mux.NewRouter()
	v1.RegisterV1Routes(router, handler)

	// Create test server
	server := httptest.NewServer(router)

	return server
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test server
	server := setupAPITestServer(t)
	defer server.Close()

	// Create HTTP client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Make request
	resp, err := client.Get(fmt.Sprintf("%s/api/v1/health", server.URL))
	require.NoError(t, err)

	// Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var healthResp v1.HealthResponse
	err = json.NewDecoder(resp.Body).Decode(&healthResp)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response fields
	assert.Equal(t, "ok", healthResp.Status)
	assert.NotEmpty(t, healthResp.Version)
}

// TestVersionEndpoint tests the version endpoint
func TestVersionEndpoint(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test server
	server := setupAPITestServer(t)
	defer server.Close()

	// Create HTTP client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Make request
	resp, err := client.Get(fmt.Sprintf("%s/api/v1/version", server.URL))
	require.NoError(t, err)

	// Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var versionResp v1.VersionResponse
	err = json.NewDecoder(resp.Body).Decode(&versionResp)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response fields
	assert.NotEmpty(t, versionResp.Version)
	assert.NotEmpty(t, versionResp.GitCommit)
	assert.NotEmpty(t, versionResp.GoVersion)
}

// TestScanEndpoint tests the scan endpoint
func TestScanEndpoint(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test server
	server := setupAPITestServer(t)
	defer server.Close()

	// Create HTTP client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Create request body
	reqBody := v1.ScanRequest{
		URL: "https://example.com",
		Options: map[string]interface{}{
			"max_depth": 1,
			"timeout":   5,
		},
	}

	// Marshal request body
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Make request
	resp, err := client.Post(
		fmt.Sprintf("%s/api/v1/scan", server.URL),
		"application/json",
		bytes.NewBuffer(body),
	)
	require.NoError(t, err)

	// Check status code
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Parse response
	var scanResp map[string]string
	err = json.NewDecoder(resp.Body).Decode(&scanResp)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response fields
	assert.NotEmpty(t, scanResp["id"])
	assert.Equal(t, "running", scanResp["status"])
}

// TestAnalyzeEndpoint tests the analyze endpoint
func TestAnalyzeEndpoint(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test server
	server := setupAPITestServer(t)
	defer server.Close()

	// Create HTTP client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Create request body
	reqBody := v1.AnalyzeRequest{
		URL:        "https://example.com/bundle.js",
		BundleType: "webpack",
		Options: map[string]interface{}{
			"detect_frameworks":    true,
			"extract_dependencies": true,
		},
	}

	// Marshal request body
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Make request
	resp, err := client.Post(
		fmt.Sprintf("%s/api/v1/analyze", server.URL),
		"application/json",
		bytes.NewBuffer(body),
	)
	require.NoError(t, err)

	// Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response (just check that it's a valid JSON)
	var analyzeResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&analyzeResp)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response fields
	assert.NotEmpty(t, analyzeResp["id"])
	assert.Equal(t, reqBody.URL, analyzeResp["url"])
}

// TestPredictEndpoint tests the predict endpoint
func TestPredictEndpoint(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test server
	server := setupAPITestServer(t)
	defer server.Close()

	// Create HTTP client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Create request body
	reqBody := v1.PredictRequest{
		Code: `function processInput(input) { eval(input); }`,
		Options: map[string]interface{}{
			"threshold": 0.5,
		},
	}

	// Marshal request body
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Make request
	resp, err := client.Post(
		fmt.Sprintf("%s/api/v1/ml/predict", server.URL),
		"application/json",
		bytes.NewBuffer(body),
	)
	require.NoError(t, err)

	// Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var predictResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&predictResp)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response fields
	assert.NotEmpty(t, predictResp["id"])
	assert.NotNil(t, predictResp["predictions"])
}
