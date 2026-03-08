.PHONY: build test test.integration

build:
	mkdir -p bin
	go build -o bin/cvefix .

test:
	go test ./...

test.integration:
	go test -tags=integration ./integration -v
