//go:build fakeagentfixture

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type fakeAgentInvocation struct {
	Timestamp string            `json:"timestamp"`
	Args      []string          `json:"args"`
	CWD       string            `json:"cwd"`
	Env       map[string]string `json:"env"`
	Stdin     string            `json:"stdin"`
}

func main() {
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read stdin: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		fail("get cwd: %v", err)
	}

	record := fakeAgentInvocation{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Args:      append([]string(nil), os.Args[1:]...),
		CWD:       cwd,
		Env:       patchpilotEnv(),
		Stdin:     string(stdin),
	}
	if err := appendInvocation(record); err != nil {
		fail("append invocation: %v", err)
	}

	if outputPath := outputFilePath(os.Args[1:]); outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			fail("create output dir: %v", err)
		}
		if err := os.WriteFile(outputPath, []byte("fake-agent-output\n"), 0o644); err != nil {
			fail("write output file: %v", err)
		}
	}
}

func patchpilotEnv() map[string]string {
	result := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(key, "PATCHPILOT_") {
			result[key] = value
		}
	}
	return result
}

func appendInvocation(record fakeAgentInvocation) error {
	recordPath := strings.TrimSpace(os.Getenv("FAKE_AGENT_RECORD_PATH"))
	if recordPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(recordPath), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(recordPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if err := json.NewEncoder(writer).Encode(record); err != nil {
		return err
	}
	return writer.Flush()
}

func outputFilePath(args []string) string {
	for index := 0; index < len(args); index++ {
		if args[index] == "-o" && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func fail(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
