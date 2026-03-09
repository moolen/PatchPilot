.PHONY: build build.app test test.integration lint.install lint

LINT_VERSION ?= v2.4.0
LINT_TOOLS_DIR ?= $(CURDIR)/.cache/tools
LINT_GOMODCACHE ?= $(CURDIR)/.cache/gomod
LINT_GOCACHE ?= $(CURDIR)/.cache/gobuild
LINT_BIN ?= $(LINT_TOOLS_DIR)/bin/golangci-lint

build:
	mkdir -p bin
	go build -o bin/patchpilot ./cmd/patchpilot
	go build -o bin/patchpilot-app ./cmd/patchpilot-app

build.app:
	mkdir -p bin
	go build -o bin/patchpilot-app ./cmd/patchpilot-app

test:
	go test ./...

test.integration:
	go test -tags=integration ./integration -v

lint.install:
	mkdir -p "$(LINT_TOOLS_DIR)/bin" "$(LINT_GOMODCACHE)" "$(LINT_GOCACHE)"
	GOBIN="$(LINT_TOOLS_DIR)/bin" GOMODCACHE="$(LINT_GOMODCACHE)" GOCACHE="$(LINT_GOCACHE)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION)

lint: lint.install
	GOMODCACHE="$(LINT_GOMODCACHE)" GOCACHE="$(LINT_GOCACHE)" "$(LINT_BIN)" run ./...
