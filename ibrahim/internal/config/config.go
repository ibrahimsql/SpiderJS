package config

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server struct {
		Host  string `yaml:"host"`
		Port  int    `yaml:"port"`
		Debug bool   `yaml:"debug"`
	} `yaml:"server"`

	// Web configuration
	Web struct {
		Port         int    `yaml:"port"`
		TemplateDir  string `yaml:"template_dir"`
		StaticDir    string `yaml:"static_dir"`
		ReadTimeout  int    `yaml:"read_timeout"`
		WriteTimeout int    `yaml:"write_timeout"`
		IdleTimeout  int    `yaml:"idle_timeout"`
	} `yaml:"web"`

	// Database configuration
	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
		SSLMode  string `yaml:"sslmode"`
	} `yaml:"database"`

	// Logging configuration
	Logging struct {
		Level string `yaml:"level"`
		File  string `yaml:"file"`
	} `yaml:"logging"`

	// Scanner configuration
	Scanner struct {
		MaxDepth      int `yaml:"max_depth"`
		MaxScripts    int `yaml:"max_scripts"`
		Timeout       int `yaml:"timeout"`
		WorkerCount   int `yaml:"worker_count"`
		RetryCount    int `yaml:"retry_count"`
		RetryInterval int `yaml:"retry_interval"`
	} `yaml:"scanner"`

	// ML configuration
	ML struct {
		ModelPath   string  `yaml:"model_path"`
		Threshold   float64 `yaml:"threshold"`
		BatchSize   int     `yaml:"batch_size"`
		MaxTokens   int     `yaml:"max_tokens"`
		UseGPU      bool    `yaml:"use_gpu"`
		DeviceID    int     `yaml:"device_id"`
		ModelConfig string  `yaml:"model_config"`
	} `yaml:"ml"`

	URL           string        `json:"url" yaml:"url" validate:"required,url"`
	Timeout       time.Duration `json:"timeout" yaml:"timeout" validate:"min=1s,max=300s"`
	MaxDepth      int           `json:"max_depth" yaml:"max_depth" validate:"min=1,max=10"`
	UserAgent     string        `json:"user_agent" yaml:"user_agent"`
	Headers       []string      `json:"headers" yaml:"headers"`
	Concurrent    int           `json:"concurrent" yaml:"concurrent" validate:"min=1,max=100"`
	Output        string        `json:"output" yaml:"output"`
	Format        string        `json:"format" yaml:"format" validate:"oneof=console json html xml"`
	LogLevel      string        `json:"log_level" yaml:"log_level" validate:"oneof=debug info warn error"`
	LogFile       string        `json:"log_file" yaml:"log_file"`
	NoColor       bool          `json:"no_color" yaml:"no_color"`
	Proxy         string        `json:"proxy" yaml:"proxy"`
	SkipTLSVerify bool          `json:"skip_tls_verify" yaml:"skip_tls_verify"`
	Cookies       []string      `json:"cookies" yaml:"cookies"`

	// Scanner options
	ScanOptions ScanOptions `json:"scan_options" yaml:"scan_options"`

	// Analyzer options
	AnalyzerOptions AnalyzerOptions `yaml:"analyzer_options"`
}

// ScanOptions contains scanner-specific configuration
type ScanOptions struct {
	IncludeXSS         bool `json:"include_xss" yaml:"include_xss"`
	IncludeInjection   bool `json:"include_injection" yaml:"include_injection"`
	IncludeCSRF        bool `json:"include_csrf" yaml:"include_csrf"`
	IncludeCORS        bool `json:"include_cors" yaml:"include_cors"`
	IncludeHeaders     bool `json:"include_headers" yaml:"include_headers"`
	IncludeCookies     bool `json:"include_cookies" yaml:"include_cookies"`
	IncludeSupplyChain bool `json:"include_supply_chain" yaml:"include_supply_chain"`
	IncludePrototype   bool `json:"include_prototype" yaml:"include_prototype"`
	IncludeSubdomains  bool `json:"include_subdomains" yaml:"include_subdomains"`
	ActiveScan         bool `json:"active_scan" yaml:"active_scan"`
	FuzzLevel          int  `json:"fuzz_level" yaml:"fuzz_level" validate:"min=0,max=3"`
}

// AnalyzerOptions represents options for analyzer
type AnalyzerOptions struct {
	IncludeSourceMap     bool `yaml:"include_source_map"`
	ExtractDependencies  bool `yaml:"extract_dependencies"`
	CheckVulnerabilities bool `yaml:"check_vulnerabilities"`
	DetectFrameworks     bool `yaml:"detect_frameworks"`
	Verbose              bool `yaml:"verbose"`
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.URL == "" {
		return errors.New("URL cannot be empty")
	}

	if _, err := url.Parse(c.URL); err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	if c.Timeout < time.Second || c.Timeout > 300*time.Second {
		return errors.New("timeout must be between 1s and 300s")
	}

	if c.MaxDepth < 1 || c.MaxDepth > 10 {
		return errors.New("max_depth must be between 1 and 10")
	}

	if c.Concurrent < 1 || c.Concurrent > 100 {
		return errors.New("concurrent must be between 1 and 100")
	}

	if c.Format != "" && c.Format != "console" && c.Format != "json" && c.Format != "html" && c.Format != "xml" {
		return errors.New("format must be one of: console, json, html, xml")
	}

	if c.LogLevel != "" && c.LogLevel != "debug" && c.LogLevel != "info" && c.LogLevel != "warn" && c.LogLevel != "error" {
		return errors.New("log_level must be one of: debug, info, warn, error")
	}

	if c.Proxy != "" {
		if _, err := url.Parse(c.Proxy); err != nil {
			return fmt.Errorf("invalid proxy URL format: %w", err)
		}
	}

	if c.ScanOptions.FuzzLevel < 0 || c.ScanOptions.FuzzLevel > 3 {
		return errors.New("fuzz_level must be between 0 and 3")
	}

	return nil
}

// SetDefaults sets default values for the configuration
func (c *Config) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.MaxDepth == 0 {
		c.MaxDepth = 3
	}
	if c.UserAgent == "" {
		c.UserAgent = "SpiderJS/1.0.0"
	}
	if c.Concurrent == 0 {
		c.Concurrent = 10
	}
	if c.Format == "" {
		c.Format = "console"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	// Default scan options
	if c.ScanOptions.FuzzLevel == 0 {
		c.ScanOptions.FuzzLevel = 1
	}

	// Set default server configuration
	if c.Server.Host == "" {
		c.Server.Host = "localhost"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}

	// Set default web configuration
	if c.Web.Port == 0 {
		c.Web.Port = 8081
	}
	if c.Web.TemplateDir == "" {
		c.Web.TemplateDir = "web/templates"
	}
	if c.Web.StaticDir == "" {
		c.Web.StaticDir = "web/static"
	}
	if c.Web.ReadTimeout == 0 {
		c.Web.ReadTimeout = 10
	}
	if c.Web.WriteTimeout == 0 {
		c.Web.WriteTimeout = 10
	}
	if c.Web.IdleTimeout == 0 {
		c.Web.IdleTimeout = 30
	}

	// Set default scanner configuration
	if c.Scanner.MaxDepth == 0 {
		c.Scanner.MaxDepth = 3
	}
	if c.Scanner.MaxScripts == 0 {
		c.Scanner.MaxScripts = 100
	}
	if c.Scanner.Timeout == 0 {
		c.Scanner.Timeout = 30
	}
	if c.Scanner.WorkerCount == 0 {
		c.Scanner.WorkerCount = 5
	}
	if c.Scanner.RetryCount == 0 {
		c.Scanner.RetryCount = 3
	}
	if c.Scanner.RetryInterval == 0 {
		c.Scanner.RetryInterval = 5
	}

	// Set default ML configuration
	if c.ML.ModelPath == "" {
		c.ML.ModelPath = "configs/ml/model.json"
	}
	if c.ML.Threshold == 0 {
		c.ML.Threshold = 0.75
	}
	if c.ML.BatchSize == 0 {
		c.ML.BatchSize = 32
	}
	if c.ML.MaxTokens == 0 {
		c.ML.MaxTokens = 1024
	}

	// Set default logging configuration
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.File == "" {
		c.Logging.File = "logs/spiderjs.log"
	}

	// Set default analyzer options
	if c.AnalyzerOptions.IncludeSourceMap == false {
		c.AnalyzerOptions.IncludeSourceMap = true
	}
	if c.AnalyzerOptions.ExtractDependencies == false {
		c.AnalyzerOptions.ExtractDependencies = true
	}
	if c.AnalyzerOptions.CheckVulnerabilities == false {
		c.AnalyzerOptions.CheckVulnerabilities = true
	}
	if c.AnalyzerOptions.DetectFrameworks == false {
		c.AnalyzerOptions.DetectFrameworks = true
	}
	if c.AnalyzerOptions.Verbose == false {
		c.AnalyzerOptions.Verbose = true
	}
}
