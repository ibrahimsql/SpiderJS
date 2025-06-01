package debug

import (
	"net/http"
	httppprof "net/http/pprof"
	"runtime"
	rtpprof "runtime/pprof"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
)

// ProfilerHandler handles profiling requests
type ProfilerHandler struct {
	log   *logger.Logger
	debug bool
}

// NewProfilerHandler creates a new profiler handler
func NewProfilerHandler(log *logger.Logger, debug bool) *ProfilerHandler {
	return &ProfilerHandler{
		log:   log,
		debug: debug,
	}
}

// RegisterRoutes registers the profiler routes
func (h *ProfilerHandler) RegisterRoutes(mux *http.ServeMux) {
	if !h.debug {
		h.log.Warn("Profiler routes are disabled because debug mode is off")
		return
	}

	h.log.Info("Registering profiler routes")

	// Register standard pprof handlers
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)

	// Register heap, goroutine and threadcreate profiles
	mux.HandleFunc("/debug/pprof/heap", func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Serving heap profile")
		runtime.GC() // run GC before taking the heap profile
		rtpprof.Lookup("heap").WriteTo(w, 0)
	})

	mux.HandleFunc("/debug/pprof/goroutine", func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Serving goroutine profile")
		rtpprof.Lookup("goroutine").WriteTo(w, 0)
	})

	mux.HandleFunc("/debug/pprof/threadcreate", func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Serving threadcreate profile")
		rtpprof.Lookup("threadcreate").WriteTo(w, 0)
	})

	mux.HandleFunc("/debug/pprof/block", func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Serving block profile")
		rtpprof.Lookup("block").WriteTo(w, 0)
	})

	mux.HandleFunc("/debug/pprof/mutex", func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Serving mutex profile")
		rtpprof.Lookup("mutex").WriteTo(w, 0)
	})

	// Custom CPU profile endpoint with duration parameter
	mux.HandleFunc("/debug/pprof/cpu", func(w http.ResponseWriter, r *http.Request) {
		// Parse duration from query parameter
		durationStr := r.URL.Query().Get("duration")
		if durationStr == "" {
			durationStr = "30s" // Default duration
		}

		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			h.log.Error("Invalid duration", "error", err)
			http.Error(w, "Invalid duration: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Cap the duration to a maximum of 5 minutes
		if duration > 5*time.Minute {
			h.log.Warn("Duration too long, capping to 5 minutes", "requested", duration)
			duration = 5 * time.Minute
		}

		h.log.Info("Starting CPU profile", "duration", duration)

		// Set content type
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=profile.pprof")

		// Start the CPU profile
		if err := rtpprof.StartCPUProfile(w); err != nil {
			h.log.Error("Failed to start CPU profile", "error", err)
			http.Error(w, "Failed to start CPU profile: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Stop the CPU profile after the specified duration
		time.Sleep(duration)
		rtpprof.StopCPUProfile()

		h.log.Info("CPU profile completed", "duration", duration)
	})

	h.log.Info("Profiler routes registered")
}
