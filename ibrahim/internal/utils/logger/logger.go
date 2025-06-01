package logger

import (
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

// For testing purposes, so we can mock os.Exit
var osExit = os.Exit

// Logger extends logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
}

// NewLogger creates a new logger instance with default configuration
func NewLogger() *Logger {
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	log.SetLevel(logrus.InfoLevel)

	// Check environment variables for configuration
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		log.SetLevel(parseLevel(level))
	}

	if format := os.Getenv("LOG_FORMAT"); format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	}

	return &Logger{Logger: log}
}

// SetVerbose sets the logger level to Debug
func (l *Logger) SetVerbose() {
	l.Logger.SetLevel(logrus.DebugLevel)
}

// SetQuiet sets the logger level to Error
func (l *Logger) SetQuiet() {
	l.Logger.SetLevel(logrus.ErrorLevel)
}

// SetLevel sets the logger level based on a string
func (l *Logger) SetLevel(level string) {
	l.Logger.SetLevel(parseLevel(level))
}

// SetFormat sets the logger formatter based on a string
func (l *Logger) SetFormat(format string) {
	if format == "json" {
		l.Logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		l.Logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}
}

// parseLevel converts a string level to logrus.Level
func parseLevel(level string) logrus.Level {
	switch level {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "warn":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	case "panic":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}

// Success logs a success message in green
func (l *Logger) Success(format string, args ...interface{}) {
	greenText := color.New(color.FgGreen).SprintfFunc()
	l.Logger.Info(greenText(format, args...))
}

// Warning logs a warning message in yellow
func (l *Logger) Warning(format string, args ...interface{}) {
	yellowText := color.New(color.FgYellow).SprintfFunc()
	l.Logger.Warn(yellowText(format, args...))
}

// ErrorMsg logs an error message in red
func (l *Logger) ErrorMsg(format string, args ...interface{}) {
	redText := color.New(color.FgRed).SprintfFunc()
	l.Logger.Error(redText(format, args...))
}

// Fatal logs a fatal message in red and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	redText := color.New(color.FgRed, color.Bold).SprintfFunc()
	l.Logger.Fatal(redText(format, args...))
	osExit(1) // This line is technically unreachable in normal execution
}

// Fields type is an alias for logrus.Fields
type Fields map[string]interface{}
