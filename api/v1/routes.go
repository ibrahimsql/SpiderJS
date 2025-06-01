package v1

import (
	"net/http"

	"github.com/gorilla/mux"
)

// RegisterV1Routes registers the v1 API routes with the provided router
func RegisterV1Routes(r *mux.Router, h *Handler) {
	// Create a subrouter for the v1 API
	v1Router := r.PathPrefix("/api/v1").Subrouter()

	// System endpoints
	v1Router.HandleFunc("/health", h.HealthHandler).Methods(http.MethodGet)
	v1Router.HandleFunc("/version", h.VersionHandler).Methods(http.MethodGet)

	// Scanner endpoints
	v1Router.HandleFunc("/scan", h.ScanHandler).Methods(http.MethodPost)
	v1Router.HandleFunc("/scan/{scanID}", h.GetScanResultsHandler).Methods(http.MethodGet)
	v1Router.HandleFunc("/scan/{scanID}/cancel", h.CancelScanHandler).Methods(http.MethodPost)

	// Analyzer endpoints
	v1Router.HandleFunc("/analyze", h.AnalyzeHandler).Methods(http.MethodPost)

	// ML endpoints
	v1Router.HandleFunc("/ml/predict", h.PredictHandler).Methods(http.MethodPost)
}
