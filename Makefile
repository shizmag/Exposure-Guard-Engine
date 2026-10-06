.PHONY: all build test test-race vet lint clean ci \
	tools-install tools-check integrations-test docker-build docker-smoke install-local

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

tools-install:
	./install.sh --with-tools

tools-check:
	./install.sh --check

integrations-test:
	go test -v ./integrations/...

docker-build:
	docker build -t exposureguard .

docker-smoke:
	docker run --rm exposureguard version
	docker run --rm exposureguard integrations list
	docker run --rm exposureguard doctor

install-local:
	./install.sh --engine-only

ci: vet test test-race
	@echo "All CI checks passed."
