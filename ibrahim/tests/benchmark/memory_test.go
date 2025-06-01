package benchmark

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/ibrahimsql/spiderjs/internal/analyzer/bundle"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/ibrahimsql/spiderjs/tests/helpers"
)

// BenchmarkMemoryUsage benchmarks memory usage of the bundle analyzer
func BenchmarkMemoryUsage(b *testing.B) {
	// Setup
	log := logger.NewLogger()
	analyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create a test target with sample scripts
	target, err := models.NewTarget("https://example.com")
	if err != nil {
		b.Fatalf("Failed to create target: %v", err)
	}

	// Add different types of scripts to analyze
	target.Scripts = []string{
		helpers.GetWebpackScript(),
		helpers.GetRollupScript(),
		helpers.GetViteScript(),
		helpers.GetMinifiedScript(),
	}

	// Run the garbage collector to get a clean baseline
	runtime.GC()

	// Record memory stats before the test
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	// Benchmark
	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := analyzer.Analyze(ctx, target)
		if err != nil {
			b.Fatalf("Error analyzing bundle: %v", err)
		}
	}

	b.StopTimer()

	// Record memory stats after the test
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	// Report memory usage
	b.ReportMetric(float64(memStatsAfter.Alloc-memStatsBefore.Alloc)/float64(b.N), "B/op")
	b.ReportMetric(float64(memStatsAfter.TotalAlloc-memStatsBefore.TotalAlloc)/float64(b.N), "total-alloc/op")
	b.ReportMetric(float64(memStatsAfter.Mallocs-memStatsBefore.Mallocs)/float64(b.N), "mallocs/op")
	b.ReportMetric(float64(memStatsAfter.Frees-memStatsBefore.Frees)/float64(b.N), "frees/op")
}

// BenchmarkLargeScriptMemory benchmarks memory usage with large scripts
func BenchmarkLargeScriptMemory(b *testing.B) {
	// Setup
	log := logger.NewLogger()
	analyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create a large script by repeating the minified script multiple times
	baseScript := helpers.GetMinifiedScript()
	var largeScript string

	// Create a 5MB script (approximate)
	for i := 0; i < 100; i++ {
		largeScript += baseScript
	}

	// Create test target
	target, err := models.NewTarget("https://example.com")
	if err != nil {
		b.Fatalf("Failed to create target: %v", err)
	}
	target.Scripts = []string{largeScript}

	// Run the garbage collector to get a clean baseline
	runtime.GC()

	// Record memory stats before the test
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	// Benchmark
	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := analyzer.Analyze(ctx, target)
		if err != nil {
			b.Fatalf("Error analyzing bundle: %v", err)
		}

		// Force garbage collection between iterations to measure peak memory
		if i < b.N-1 {
			runtime.GC()
		}
	}

	b.StopTimer()

	// Record memory stats after the test
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	// Report memory metrics
	b.ReportMetric(float64(len(largeScript)), "script-size")
	b.ReportMetric(float64(memStatsAfter.TotalAlloc-memStatsBefore.TotalAlloc)/float64(b.N), "total-alloc/op")
	b.ReportMetric(float64(memStatsAfter.Mallocs-memStatsBefore.Mallocs)/float64(b.N), "mallocs/op")
}

// BenchmarkConcurrentMemory benchmarks memory usage with concurrent operations
func BenchmarkConcurrentMemory(b *testing.B) {
	// Skip in short mode as this is a resource-intensive test
	if testing.Short() {
		b.Skip("Skipping concurrent memory benchmark in short mode")
	}

	// Setup
	log := logger.NewLogger()
	analyzer, err := bundle.NewAnalyzer(log)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}

	// Create different targets with different scripts
	targets := []*models.Target{}

	scripts := []string{
		helpers.GetWebpackScript(),
		helpers.GetRollupScript(),
		helpers.GetViteScript(),
		helpers.GetMinifiedScript(),
		helpers.GetAngularScript(),
	}

	for i, script := range scripts {
		target, err := models.NewTarget(fmt.Sprintf("https://example%d.com", i))
		if err != nil {
			b.Fatalf("Failed to create target: %v", err)
		}
		target.Scripts = []string{script}
		targets = append(targets, target)
	}

	// Run the garbage collector to get a clean baseline
	runtime.GC()

	// Record memory stats before the test
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	// Benchmark
	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(len(targets))

		for _, target := range targets {
			go func(t *models.Target) {
				defer wg.Done()

				_, err := analyzer.Analyze(ctx, t)
				if err != nil {
					b.Errorf("Error analyzing bundle: %v", err)
				}
			}(target)
		}

		wg.Wait()
	}

	b.StopTimer()

	// Record memory stats after the test
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	// Report memory metrics
	b.ReportMetric(float64(memStatsAfter.TotalAlloc-memStatsBefore.TotalAlloc)/float64(b.N), "total-alloc/op")
	b.ReportMetric(float64(memStatsAfter.Mallocs-memStatsBefore.Mallocs)/float64(b.N), "mallocs/op")
	b.ReportMetric(float64(len(targets)), "concurrent-jobs")
}
