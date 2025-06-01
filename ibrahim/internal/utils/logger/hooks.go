package logger

import (
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// FileHook is a hook that writes logs to a file
type FileHook struct {
	file      *os.File
	levels    []logrus.Level
	formatter logrus.Formatter
}

// NewFileHook creates a new hook that writes logs to a file
func NewFileHook(path string, levels []logrus.Level) (*FileHook, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Open file
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	return &FileHook{
		file:      file,
		levels:    levels,
		formatter: &logrus.JSONFormatter{},
	}, nil
}

// Fire is called when a log event is fired
func (hook *FileHook) Fire(entry *logrus.Entry) error {
	line, err := hook.formatter.Format(entry)
	if err != nil {
		return err
	}
	_, err = hook.file.Write(line)
	return err
}

// Levels returns the levels this hook is enabled for
func (hook *FileHook) Levels() []logrus.Level {
	return hook.levels
}

// Close closes the file
func (hook *FileHook) Close() error {
	return hook.file.Close()
}
