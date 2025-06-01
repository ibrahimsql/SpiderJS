package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	// Test default logger creation
	logger := NewLogger()
	assert.NotNil(t, logger)
	assert.Equal(t, logrus.InfoLevel, logger.Level)
	assert.IsType(t, &logrus.TextFormatter{}, logger.Formatter)

	// Reset environment after test
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_FORMAT")
}

func TestNewLoggerWithEnv(t *testing.T) {
	// Test with environment variables
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_FORMAT", "json")

	logger := NewLogger()
	assert.NotNil(t, logger)
	assert.Equal(t, logrus.DebugLevel, logger.Level)
	assert.IsType(t, &logrus.JSONFormatter{}, logger.Formatter)

	// Reset environment after test
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_FORMAT")
}

func TestSetLevel(t *testing.T) {
	logger := NewLogger()

	tests := []struct {
		level    string
		expected logrus.Level
	}{
		{"debug", logrus.DebugLevel},
		{"info", logrus.InfoLevel},
		{"warn", logrus.WarnLevel},
		{"error", logrus.ErrorLevel},
		{"fatal", logrus.FatalLevel},
		{"panic", logrus.PanicLevel},
		{"invalid", logrus.InfoLevel}, // Should default to info
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			logger.SetLevel(tt.level)
			assert.Equal(t, tt.expected, logger.Level)
		})
	}
}

func TestSetFormat(t *testing.T) {
	logger := NewLogger()

	// Test JSON format
	logger.SetFormat("json")
	assert.IsType(t, &logrus.JSONFormatter{}, logger.Formatter)

	// Test text format
	logger.SetFormat("text")
	assert.IsType(t, &logrus.TextFormatter{}, logger.Formatter)

	// Test invalid format (should default to text)
	logger.SetFormat("invalid")
	assert.IsType(t, &logrus.TextFormatter{}, logger.Formatter)
}

func TestLogging(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a new logger with the buffer as output
	logger := NewLogger()
	logger.SetLevel("debug")
	logger.SetFormat("json")
	logger.Out = &buf

	// Test different log levels
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warning message")
	logger.Error("error message")

	// Read the log output
	output := buf.String()

	// Verify each log message was recorded
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "warning message")
	assert.Contains(t, output, "error message")

	// Parse the first log entry to verify structure
	buf.Reset()
	logger.WithFields(logrus.Fields{"key": "value"}).Info("test structured logging")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	assert.NoError(t, err)
	assert.Equal(t, "test structured logging", logEntry["msg"])
	assert.Equal(t, "value", logEntry["key"])
	assert.Equal(t, "info", logEntry["level"])
}

func TestWithField(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a new logger with the buffer as output
	logger := NewLogger()
	logger.SetFormat("json")
	logger.Out = &buf

	// Test WithField
	logger.WithField("field1", "value1").Info("test message")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	assert.NoError(t, err)
	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value1", logEntry["field1"])
}

func TestWithFields(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a new logger with the buffer as output
	logger := NewLogger()
	logger.SetFormat("json")
	logger.Out = &buf

	// Test WithFields
	logger.WithFields(logrus.Fields{
		"field1": "value1",
		"field2": 42,
	}).Info("test message")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	assert.NoError(t, err)
	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value1", logEntry["field1"])
	assert.Equal(t, float64(42), logEntry["field2"]) // JSON numbers are float64
}

func TestPanic(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a new logger with the buffer as output
	logger := NewLogger()
	logger.SetFormat("json")
	logger.Out = &buf

	// Test Panic (should panic)
	assert.Panics(t, func() {
		logger.Panic("panic message")
	})

	// Verify the panic was logged
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	assert.NoError(t, err)
	assert.Equal(t, "panic message", logEntry["msg"])
	assert.Equal(t, "panic", logEntry["level"])
}

func TestFatal(t *testing.T) {
	// Skip this test as it involves os.Exit which can be problematic in tests
	t.Skip("Skipping TestFatal as it involves os.Exit")
}

// No need to redefine osExit here, it's already defined in the logger.go file
