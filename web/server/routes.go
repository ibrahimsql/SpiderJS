package server

import (
	"net/http"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/web/debug"
	"github.com/ibrahimsql/spiderjs/web/handlers"
	"github.com/ibrahimsql/spiderjs/web/middleware"
)

// Routes configures and registers all routes for the server
func RegisterRoutes(
	mux *http.ServeMux,
	cfg *config.Config,
	log *logger.Logger,
	webHandler *handlers.WebHandler,
) {
	// Apply global middleware to mux
	middleware.ApplyMiddleware(mux,
		middleware.Logger(log),
		middleware.Recovery(log),
		middleware.Security(),
		middleware.CORS(),
	)

	// Register web routes
	webHandler.RegisterRoutes(mux)

	// Register debug routes if enabled
	if cfg.Server.Debug {
		log.Info("Debug mode enabled, registering debug routes")

		// Create debug handlers
		debugHandler := debug.NewDebugHandler(log, true)
		profilerHandler := debug.NewProfilerHandler(log, true)

		// Register debug routes
		debugHandler.RegisterRoutes(mux)
		profilerHandler.RegisterRoutes(mux)
	}

	// Register not found handler
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Page not found"))
	})
}
