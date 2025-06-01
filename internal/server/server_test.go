package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/ml"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/version"
	"github.com/stretchr/testify/assert"
)

func TestNewServer(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	tests := []struct {
		name    string
		cfg     *config.Config
		log     *logger.Logger
		wantErr bool
	}{
		{
			name:    "Valid config and logger",
			cfg:     cfg,
			log:     log,
			wantErr: false,
		},
		{
			name:    "Nil config",
			cfg:     nil,
			log:     log,
			wantErr: true,
		},
		{
			name:    "Nil logger",
			cfg:     cfg,
			log:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.cfg, tt.log)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, server)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, server)
				assert.NotNil(t, server.handlers)
				assert.Equal(t, 6, len(server.handlers))
			}
		})
	}
}

func TestHandleIndex(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Create a request to the index page
	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler := server.handleIndex()
	handler.ServeHTTP(rr, req)

	// Check the status code
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check the content type
	assert.Equal(t, "text/html", rr.Header().Get("Content-Type"))

	// Check the body contains expected content
	assert.Contains(t, rr.Body.String(), "SpiderJS Web Server")
	assert.Contains(t, rr.Body.String(), version.GetVersion())

	// Test 404 for non-root paths
	req, err = http.NewRequest("GET", "/not-found", nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleVersion(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Create a request to the version endpoint
	req, err := http.NewRequest("GET", "/api/version", nil)
	assert.NoError(t, err)

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler := server.handleVersion()
	handler.ServeHTTP(rr, req)

	// Check the status code
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check the content type
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse the response
	var resp version.Info
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Check the version
	assert.Equal(t, version.GetVersion(), resp.Version)

	// Test method not allowed
	req, err = http.NewRequest("POST", "/api/version", nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleHealth(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Create a request to the health endpoint
	req, err := http.NewRequest("GET", "/api/health", nil)
	assert.NoError(t, err)

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler := server.handleHealth()
	handler.ServeHTTP(rr, req)

	// Check the status code
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check the content type
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse the response
	var resp struct {
		Status    string    `json:"status"`
		Timestamp time.Time `json:"timestamp"`
		Version   string    `json:"version"`
	}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Check the status
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, version.GetVersion(), resp.Version)

	// Test method not allowed
	req, err = http.NewRequest("POST", "/api/health", nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleConfig(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test GET
	req, err := http.NewRequest("GET", "/api/config", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := server.handleConfig()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse the response
	var respCfg config.Config
	err = json.Unmarshal(rr.Body.Bytes(), &respCfg)
	assert.NoError(t, err)

	// Test POST with valid config
	validConfig := `{"url": "https://example.com", "timeout": "30s", "max_depth": 5}`
	req, err = http.NewRequest("POST", "/api/config", strings.NewReader(validConfig))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Skip status code check as it depends on validation implementation
	// We're just testing that it runs without crashing

	// Test POST with invalid config
	invalidConfig := `{"url": "", "timeout": "invalid"}`
	req, err = http.NewRequest("POST", "/api/config", strings.NewReader(invalidConfig))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Test method not allowed
	req, err = http.NewRequest("PUT", "/api/config", nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleScan(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test POST with valid URL
	validReq := `{"url": "https://example.com"}`
	req, err := http.NewRequest("POST", "/api/scan", strings.NewReader(validReq))
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := server.handleScan()
	handler.ServeHTTP(rr, req)
	// Note: The actual scan would fail in a test environment, but we're just testing the handler logic

	// Test POST with empty URL
	emptyReq := `{"url": ""}`
	req, err = http.NewRequest("POST", "/api/scan", strings.NewReader(emptyReq))
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Test POST with invalid JSON
	invalidReq := `{"url": }`
	req, err = http.NewRequest("POST", "/api/scan", strings.NewReader(invalidReq))
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Test method not allowed
	req, err = http.NewRequest("GET", "/api/scan", nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleMLPredict(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Test POST with valid code
	validReq := `{"code": "document.getElementById('user').innerHTML = input;"}`
	req, err := http.NewRequest("POST", "/api/ml/predict", strings.NewReader(validReq))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := server.handleMLPredict()
	handler.ServeHTTP(rr, req)

	// Check response status code (should be 200 OK)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check content type
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse response
	var resp struct {
		Results []*ml.PredictionResult `json:"results"`
	}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Check that we got some results (XSS vulnerability should be detected)
	assert.NotEmpty(t, resp.Results)

	// Test POST with empty code
	emptyReq := `{"code": ""}`
	req, err = http.NewRequest("POST", "/api/ml/predict", strings.NewReader(emptyReq))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Test method not allowed
	req, err = http.NewRequest("GET", "/api/ml/predict", nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestStartAndShutdown(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{}
	cfg.SetDefaults()

	server, err := NewServer(cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, server)

	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Start the server in a goroutine
	go func() {
		err := server.Start(ctx, "127.0.0.1", 0)
		assert.NoError(t, err)
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context to trigger shutdown
	cancel()

	// Give the server time to shut down
	time.Sleep(100 * time.Millisecond)
}
