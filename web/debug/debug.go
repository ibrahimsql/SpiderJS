package debug

import (
	"encoding/json"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
)

// DebugHandler handles debug requests
type DebugHandler struct {
	log       *logger.Logger
	debug     bool
	startTime time.Time
}

// NewDebugHandler creates a new debug handler
func NewDebugHandler(log *logger.Logger, debug bool) *DebugHandler {
	return &DebugHandler{
		log:       log,
		debug:     debug,
		startTime: time.Now(),
	}
}

// MemoryStats returns memory statistics
func (h *DebugHandler) MemoryStats(w http.ResponseWriter, r *http.Request) {
	if !h.debug {
		http.Error(w, "Debug mode is disabled", http.StatusForbidden)
		return
	}

	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	response := map[string]interface{}{
		"alloc":        stats.Alloc,
		"total_alloc":  stats.TotalAlloc,
		"sys":          stats.Sys,
		"heap_alloc":   stats.HeapAlloc,
		"heap_sys":     stats.HeapSys,
		"heap_idle":    stats.HeapIdle,
		"heap_inuse":   stats.HeapInuse,
		"heap_objects": stats.HeapObjects,
		"num_gc":       stats.NumGC,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// BuildInfo returns build information
func (h *DebugHandler) BuildInfo(w http.ResponseWriter, r *http.Request) {
	if !h.debug {
		http.Error(w, "Debug mode is disabled", http.StatusForbidden)
		return
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		http.Error(w, "Failed to read build info", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"go_version": info.GoVersion,
		"path":       info.Path,
		"main":       info.Main,
	}

	// Add dependencies
	deps := make([]map[string]string, 0, len(info.Deps))
	for _, dep := range info.Deps {
		deps = append(deps, map[string]string{
			"path":    dep.Path,
			"version": dep.Version,
		})
	}
	response["dependencies"] = deps

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RuntimeInfo returns runtime information
func (h *DebugHandler) RuntimeInfo(w http.ResponseWriter, r *http.Request) {
	if !h.debug {
		http.Error(w, "Debug mode is disabled", http.StatusForbidden)
		return
	}

	response := map[string]interface{}{
		"go_version":    runtime.Version(),
		"go_os":         runtime.GOOS,
		"go_arch":       runtime.GOARCH,
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
		"uptime":        time.Since(h.startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// TraceHandler returns runtime traces
func (h *DebugHandler) TraceHandler(w http.ResponseWriter, r *http.Request) {
	if !h.debug {
		http.Error(w, "Debug mode is disabled", http.StatusForbidden)
		return
	}

	// Return a stack trace
	stack := debug.Stack()

	w.Header().Set("Content-Type", "text/plain")
	w.Write(stack)
}

// HealthCheck performs a health check
func (h *DebugHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status": "ok",
		"uptime": time.Since(h.startTime).String(),
		"time":   time.Now().Format(time.RFC3339),
		"debug":  h.debug,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RegisterRoutes registers the debug routes
func (h *DebugHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/debug/memory", h.MemoryStats)
	mux.HandleFunc("/debug/build", h.BuildInfo)
	mux.HandleFunc("/debug/runtime", h.RuntimeInfo)
	mux.HandleFunc("/debug/trace", h.TraceHandler)
	mux.HandleFunc("/debug/health", h.HealthCheck)
}
