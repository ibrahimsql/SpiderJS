package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		options *ClientOptions
		wantErr bool
	}{
		{
			name: "Valid options",
			options: &ClientOptions{
				Timeout:   10 * time.Second,
				UserAgent: "TestAgent",
			},
			wantErr: false,
		},
		{
			name:    "Nil options",
			options: nil,
			wantErr: false,
		},
		{
			name: "Invalid proxy",
			options: &ClientOptions{
				Timeout:   10 * time.Second,
				UserAgent: "TestAgent",
				Proxy:     "://invalid-url",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.options)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotNil(t, client.Client)
				assert.NotNil(t, client.options)
			}
		})
	}
}

func TestGet(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/success" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		} else if r.URL.Path == "/notfound" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		} else if r.URL.Path == "/timeout" {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("timeout"))
		}
	}))
	defer server.Close()

	client, err := NewClient(&ClientOptions{
		Timeout: 10 * time.Second,
	})
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test successful GET request
	resp, err := client.Get(context.Background(), server.URL+"/success")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test 404 response
	resp, err = client.Get(context.Background(), server.URL+"/notfound")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err = client.Get(ctx, server.URL+"/success")
	assert.Error(t, err)
	assert.Nil(t, resp)

	// Test with timeout
	timeoutClient, err := NewClient(&ClientOptions{
		Timeout: 50 * time.Millisecond,
	})
	assert.NoError(t, err)
	resp, err = timeoutClient.Get(context.Background(), server.URL+"/timeout")
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestPost(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.URL.Path == "/success" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		} else if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error"))
		}
	}))
	defer server.Close()

	client, err := NewClient(&ClientOptions{
		Timeout: 10 * time.Second,
	})
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Test successful POST request
	resp, err := client.Post(context.Background(), server.URL+"/success", "application/json", []byte(`{"test":"data"}`))
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test error response
	resp, err = client.Post(context.Background(), server.URL+"/error", "application/json", []byte(`{"test":"data"}`))
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err = client.Post(ctx, server.URL+"/success", "application/json", []byte(`{"test":"data"}`))
	assert.Error(t, err)
	assert.Nil(t, resp)

	// Test with invalid URL
	resp, err = client.Post(context.Background(), "invalid-url", "application/json", []byte(`{"test":"data"}`))
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestSetHeaders(t *testing.T) {
	// Create a test server that checks headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		customHeader := r.Header.Get("X-Custom-Header")

		if userAgent == "SpiderJS" && customHeader == "TestValue" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(&ClientOptions{
		Timeout: 10 * time.Second,
	})
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Set custom headers
	client.AddHeader("X-Custom-Header", "TestValue")
	client.SetUserAgent("SpiderJS")

	// Test that headers are sent correctly
	resp, err := client.Get(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSetUserAgent(t *testing.T) {
	// Create a test server that checks User-Agent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")

		if userAgent == "SpiderJS/1.0" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := NewClient(&ClientOptions{
		Timeout: 10 * time.Second,
	})
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Set user agent
	client.SetUserAgent("SpiderJS/1.0")

	// Test that user agent is sent correctly
	resp, err := client.Get(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
