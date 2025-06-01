package benchmark

import (
	"context"
	"testing"

	"github.com/ibrahimsql/spiderjs/internal/analyzer/bundle"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/ibrahimsql/spiderjs/tests/helpers"
)

// BenchmarkBundleAnalyzer benchmarks the bundle analyzer
func BenchmarkBundleAnalyzer(b *testing.B) {
	// Setup
	log := logger.NewLogger()
	analyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create a test target with a sample webpack script
	target, err := models.NewTarget("https://example.com")
	if err != nil {
		b.Fatalf("Failed to create target: %v", err)
	}
	target.Scripts = []string{helpers.WebpackScript}

	// Benchmark
	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := analyzer.Analyze(ctx, target)
		if err != nil {
			b.Fatalf("Error analyzing bundle: %v", err)
		}
	}
}

// BenchmarkDetectBundleType benchmarks the detectBundleType functionality
func BenchmarkDetectBundleType(b *testing.B) {
	// Setup
	log := logger.NewLogger()
	analyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}

	// Sample scripts
	webpackScript := helpers.WebpackScript
	rollupScript := helpers.RollupScript

	// Create a test target with the sample scripts
	target, err := models.NewTarget("https://example.com")
	if err != nil {
		b.Fatalf("Failed to create target: %v", err)
	}

	// Benchmark for Webpack
	b.Run("Webpack", func(b *testing.B) {
		target.Scripts = []string{webpackScript}
		ctx := context.Background()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := analyzer.Analyze(ctx, target)
			if err != nil {
				b.Fatalf("Error analyzing webpack bundle: %v", err)
			}
		}
	})

	// Benchmark for Rollup
	b.Run("Rollup", func(b *testing.B) {
		target.Scripts = []string{rollupScript}
		ctx := context.Background()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := analyzer.Analyze(ctx, target)
			if err != nil {
				b.Fatalf("Error analyzing rollup bundle: %v", err)
			}
		}
	})
}
