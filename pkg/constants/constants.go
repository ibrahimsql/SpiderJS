package constants

// Application constants
const (
	// ApplicationName is the name of the application
	ApplicationName = "SpiderJS"

	// DefaultConfigPath is the default path to the configuration file
	DefaultConfigPath = "configs/default.yaml"

	// DefaultLogLevel is the default log level
	DefaultLogLevel = "info"

	// DefaultHost is the default host for the web server
	DefaultHost = "127.0.0.1"

	// DefaultPort is the default port for the web server
	DefaultPort = 8080

	// DefaultTimeout is the default timeout for HTTP requests in seconds
	DefaultTimeout = 30

	// UserAgent is the default user agent for HTTP requests
	UserAgent = "SpiderJS/1.0 (+https://github.com/ibrahimsql/spiderjs)"
)

// File paths
const (
	// MLModelPath is the path to the ML model file
	MLModelPath = "configs/ml/model.json"

	// FingerprintsPath is the path to the fingerprints directory
	FingerprintsPath = "configs/fingerprints"

	// PayloadsPath is the path to the payloads directory
	PayloadsPath = "configs/payloads"

	// RulesPath is the path to the rules directory
	RulesPath = "configs/rules"
)

// Security related constants
const (
	// HighSeverity represents a high severity issue
	HighSeverity = "HIGH"

	// MediumSeverity represents a medium severity issue
	MediumSeverity = "MEDIUM"

	// LowSeverity represents a low severity issue
	LowSeverity = "LOW"

	// InfoSeverity represents an informational issue
	InfoSeverity = "INFO"
)

// JavaScript related constants
const (
	// MinificationThreshold is the threshold for detecting minified code
	MinificationThreshold = 0.1

	// CommonDependencies is a list of common JavaScript dependencies
	CommonDependencies = "react,vue,angular,jquery,lodash,moment,axios,d3"
)
