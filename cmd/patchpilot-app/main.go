package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/moolen/patchpilot/pkg/githubapp"
)

func main() {
	cfg, err := githubapp.LoadConfigFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "[patchpilot-app] ", log.LstdFlags)
	service, err := githubapp.NewService(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize app service: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/webhook", service.HandleWebhook)

	logger.Printf("listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
}
