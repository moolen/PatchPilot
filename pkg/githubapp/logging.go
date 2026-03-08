package githubapp

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type structuredLogger struct {
	logger *log.Logger
}

func newStructuredLogger(base *log.Logger) *structuredLogger {
	if base == nil {
		base = log.New(os.Stderr, "", 0)
	}
	return &structuredLogger{logger: base}
}

func (logger *structuredLogger) Log(level, message string, fields map[string]interface{}) {
	payload := map[string]interface{}{
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
		"level":   level,
		"message": message,
	}
	for key, value := range fields {
		payload[key] = value
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.logger.Printf(`{"time":%q,"level":"error","message":"failed to marshal structured log","error":%q}`, time.Now().UTC().Format(time.RFC3339Nano), err.Error())
		return
	}
	logger.logger.Print(string(data))
}
