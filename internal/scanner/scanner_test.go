package scanner

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNewScanner(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{
		URL: "https://example.com",
	}
	cfg.SetDefaults()

	tests := []struct {
		name    string
		ctx     context.Context
		cfg     *config.Config
		log     *logger.Logger
		wantErr bool
	}{
		{
			name:    "Valid context, config, and logger",
			ctx:     context.Background(),
			cfg:     cfg,
			log:     log,
			wantErr: false,
		},
		{
			name:    "Cancelled context",
			ctx:     cancelled(),
			cfg:     cfg,
			log:     log,
			wantErr: true,
		},
		{
			name:    "Nil config",
			ctx:     context.Background(),
			cfg:     nil,
			log:     log,
			wantErr: true,
		},
		{
			name:    "Nil logger",
			ctx:     context.Background(),
			cfg:     cfg,
			log:     nil,
			wantErr: true,
		},
		{
			name:    "Empty URL",
			ctx:     context.Background(),
			cfg:     &config.Config{},
			log:     log,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.ctx, tt.cfg, tt.log)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, scanner)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, scanner)
			}
		})
	}
}

func TestScan(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{
		URL: "https://example.com",
	}
	cfg.SetDefaults()

	// Create a scanner
	scanner, err := NewScanner(context.Background(), cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, scanner)

	// Test successful scan
	result, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Target)
	assert.GreaterOrEqual(t, len(result.Findings), 1)
	assert.NotZero(t, result.Duration)
	assert.NotZero(t, result.StartTime)
	assert.NotZero(t, result.EndTime)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = scanner.Scan(ctx)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGenerateReport(t *testing.T) {
	log := logger.NewLogger()
	cfg := &config.Config{
		URL: "https://example.com",
	}
	cfg.SetDefaults()

	// Create a scanner
	scanner, err := NewScanner(context.Background(), cfg, log)
	assert.NoError(t, err)
	assert.NotNil(t, scanner)

	// Create a scan result
	targetURL, _ := url.Parse("https://example.com")
	result := &ScanResult{
		Target: &models.Target{
			URL:    targetURL.String(),
			Domain: "example.com",
		},
		Findings: []*models.Finding{
			models.NewFinding(
				models.FindingTypeVulnerability,
				"Test Finding",
				models.SeverityMedium,
			),
		},
		Duration:  1 * time.Second,
		StartTime: time.Now().Add(-1 * time.Second),
		EndTime:   time.Now(),
	}

	// Test successful report generation
	err = scanner.GenerateReport(context.Background(), result)
	assert.NoError(t, err)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = scanner.GenerateReport(ctx, result)
	assert.Error(t, err)

	// Test with nil result
	err = scanner.GenerateReport(context.Background(), nil)
	assert.Error(t, err)
}

// Helper function to create a cancelled context
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
