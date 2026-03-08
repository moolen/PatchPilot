package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

var progressState = struct {
	mu      sync.RWMutex
	json    bool
	command string
	repo    string
	runID   string
}{
	json: false,
}

func configureProgressLogging(jsonOutput bool, command, repo, runID string) {
	progressState.mu.Lock()
	defer progressState.mu.Unlock()
	progressState.json = jsonOutput
	progressState.command = command
	progressState.repo = repo
	progressState.runID = runID
}

func logProgress(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	progressState.mu.RLock()
	jsonOutput := progressState.json
	command := progressState.command
	repo := progressState.repo
	runID := progressState.runID
	progressState.mu.RUnlock()

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "[cvefix] %s\n", message)
		return
	}

	event := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"level":   "info",
		"run_id":  runID,
		"command": command,
		"repo":    repo,
		"msg":     message,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[cvefix] %s\n", message)
		return
	}
	fmt.Fprintln(os.Stderr, string(encoded))
}
