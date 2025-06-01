package logger

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

// CustomFormatter formats logs with colored output
type CustomFormatter struct {
	// TimestampFormat sets the format used for timestamps
	TimestampFormat string
	// ShowColors determines if colors should be used
	ShowColors bool
}

// Format renders a log entry into a byte array
func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	// Get timestamp
	timestamp := entry.Time.Format(f.TimestampFormat)

	// Get level color
	var levelColor *color.Color
	switch entry.Level {
	case logrus.DebugLevel:
		levelColor = color.New(color.FgCyan)
	case logrus.InfoLevel:
		levelColor = color.New(color.FgBlue)
	case logrus.WarnLevel:
		levelColor = color.New(color.FgYellow)
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = color.New(color.FgRed)
	default:
		levelColor = color.New(color.FgWhite)
	}

	// Format level text
	levelText := strings.ToUpper(entry.Level.String())
	if f.ShowColors {
		levelText = levelColor.Sprint(levelText)
	}

	// Write header
	fmt.Fprintf(b, "[%s] [%s] ", timestamp, levelText)

	// Write message
	fmt.Fprintf(b, "%s", entry.Message)

	// Write fields
	if len(entry.Data) > 0 {
		b.WriteString(" ")
		f.writeFields(b, entry)
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

func (f *CustomFormatter) writeFields(b *bytes.Buffer, entry *logrus.Entry) {
	// Get sorted keys
	keys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, key := range keys {
		if i > 0 {
			b.WriteString(" ")
		}

		fmt.Fprintf(b, "%s=", key)
		f.writeValue(b, entry.Data[key])
	}
}

func (f *CustomFormatter) writeValue(b *bytes.Buffer, value interface{}) {
	switch v := value.(type) {
	case string:
		fmt.Fprintf(b, "%q", v)
	case time.Time:
		fmt.Fprintf(b, "%s", v.Format(f.TimestampFormat))
	default:
		fmt.Fprintf(b, "%v", v)
	}
}
