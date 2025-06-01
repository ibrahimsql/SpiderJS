package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/web/handlers"
	"github.com/ibrahimsql/spiderjs/web/middleware"
)

// WebServer represents the web interface server
type WebServer struct {
	log        *logger.Logger
	config     *config.Config
	webHandler *handlers.WebHandler
	server     *http.Server
	mux        *http.ServeMux
}

// NewWebServer creates a new web server
func NewWebServer(log *logger.Logger, config *config.Config) *WebServer {
	return &WebServer{
		log:    log,
		config: config,
		mux:    http.NewServeMux(),
	}
}

// Initialize sets up the web server
func (s *WebServer) Initialize(webHandler *handlers.WebHandler) error {
	s.log.Info("Initializing web server")

	// Store handler
	s.webHandler = webHandler

	// Apply middleware
	handler := middleware.Chain(
		middleware.Logger(s.log),
		middleware.Recovery(s.log),
		middleware.Security(),
		middleware.CORS(),
	)(s.mux)

	// Register routes
	s.webHandler.RegisterRoutes(s.mux)

	// Configure server
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Web.Port),
		Handler:      handler,
		ReadTimeout:  time.Duration(s.config.Web.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Web.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.Web.IdleTimeout) * time.Second,
	}

	return nil
}

// Start starts the web server
func (s *WebServer) Start() error {
	s.log.Info("Starting web server", "address", s.server.Addr)

	// Start the server in a goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("Web server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully stops the web server
func (s *WebServer) Stop(ctx context.Context) error {
	s.log.Info("Stopping web server")

	// Create a shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Shutdown the server
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.log.Error("Web server shutdown error", "error", err)
		return err
	}

	s.log.Info("Web server stopped")
	return nil
}
