.PHONY: build build.app test test.integration

build:
	mkdir -p bin
	go build -o bin/cvefix .
	go build -o bin/patchpilot-app ./cmd/patchpilot-app

build.app:
	mkdir -p bin
	go build -o bin/patchpilot-app ./cmd/patchpilot-app

test:
	go test ./...

test.integration:
	go test -tags=integration ./integration -v
