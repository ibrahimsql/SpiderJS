package middleware

import (
	"compress/gzip"
	"net/http"
	"strings"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
)

// Middleware represents a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// Chain combines multiple middleware into a single middleware
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// Logger logs information about each request
func Logger(log *logger.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a custom response writer to capture status code
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Call the next handler
			next.ServeHTTP(rw, r)

			// Log the request
			duration := time.Since(start)
			log.Info("HTTP Request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.statusCode,
				"duration", duration,
				"user_agent", r.UserAgent(),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// CORS adds Cross-Origin Resource Sharing headers
func CORS() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// Security adds security-related headers
func Security() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// Recovery handles panics and recovers gracefully
func Recovery(log *logger.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Error("Handler panicked", "error", err, "path", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Internal Server Error"))
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter is a wrapper for http.ResponseWriter that captures the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before writing it
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Compression applies gzip compression to the response
func Compression() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the client accepts gzip encoding
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Create a gzip writer
			gz, err := gzip.NewWriterLevel(w, gzip.DefaultCompression)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			defer gz.Close()

			// Create a gzipped response writer
			gzw := &gzipResponseWriter{
				ResponseWriter: w,
				Writer:         gz,
			}

			// Set content encoding header
			w.Header().Set("Content-Encoding", "gzip")

			// Call the next handler with the gzipped writer
			next.ServeHTTP(gzw, r)
		})
	}
}

// gzipResponseWriter is a wrapper for http.ResponseWriter that writes to a gzip.Writer
type gzipResponseWriter struct {
	http.ResponseWriter
	Writer *gzip.Writer
}

// Write writes the data to the gzip writer
func (gzw *gzipResponseWriter) Write(data []byte) (int, error) {
	return gzw.Writer.Write(data)
}

// ApplyMiddleware applies middleware to an http.ServeMux
func ApplyMiddleware(mux *http.ServeMux, middlewares ...Middleware) http.Handler {
	var handler http.Handler = mux
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
