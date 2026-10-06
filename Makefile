.PHONY: all build test test-race vet lint clean ci \
	tools-install tools-check integrations-test docker-build docker-smoke install-local \
	generate manifest-check release-smoke

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

generate:
	go run ./pkg/integration/gen/sync_manifest.go

manifest-check: generate
	@git diff --exit-code pkg/integration/tools_lock_gen.go || (echo "Error: Embedded tool manifest has drifted from canonical /tools.lock.json. Run 'make generate' and commit." && exit 1)

release-smoke: build
	@echo "==> Running release artifact smoke tests..."
	./bin/exposureguard version --format json
	./bin/exposureguard doctor
	./bin/exposureguard profiles list
	./bin/exposureguard integrations list
	./bin/exposureguard checks list
	./bin/exposureguard scan https://example.com --profile standard --plan
	./bin/exposureguard snapshot hash testdata/snapshots/snapshot_v1_expected.json
	./bin/exposureguard diff testdata/snapshots/diff_source_map_old.json testdata/snapshots/diff_source_map_new.json
	@echo "==> Release smoke tests passed successfully."

ci: manifest-check vet test test-race release-smoke
	@echo "All CI checks passed."
