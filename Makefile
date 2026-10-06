.PHONY: all build test test-race vet lint clean ci

BIN_DIR := bin
BINARY := $(BIN_DIR)/exposureguard
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/exposureguard/exposureguard/internal/buildinfo.Version=$(VERSION) \
	-X github.com/exposureguard/exposureguard/internal/buildinfo.GitCommit=$(COMMIT) \
	-X github.com/exposureguard/exposureguard/internal/buildinfo.BuildDate=$(BUILD_DATE)

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/exposureguard

test:
	go test -v ./...

test-race:
	go test -race -v ./...

vet:
	go vet ./...

lint: vet
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, vet passed"

clean:
	rm -rf $(BIN_DIR)

ci: vet test test-race
	@echo "All CI checks passed."
