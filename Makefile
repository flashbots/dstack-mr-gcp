.PHONY: build install clean test fmt vet lint help
.PHONY: release release-snapshot
.DEFAULT_GOAL := help

# Variables
BINARY_NAME=dstack-mr-gcp
BUILD_DIR=build
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -w -s"

## help: Display this help message
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'

## build: Build the binary into build/
build:
	@echo "Building $(BINARY_NAME) into $(BUILD_DIR)/..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

## install: Install the binary to $GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) .

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BUILD_DIR)/$(BINARY_NAME)
	rm -rf dist/

## test: Run tests
test:
	@echo "Running tests..."
	go test -v ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## lint: Run golangci-lint (requires golangci-lint to be installed)
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

## tidy: Tidy go modules
tidy:
	@echo "Tidying go modules..."
	go mod tidy

## release: Create a release with GoReleaser (requires GITHUB_TOKEN)
release:
	@echo "Creating release with GoReleaser..."
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install from https://goreleaser.com/install/" && exit 1)
	@test -n "$(GITHUB_TOKEN)" || (echo "GITHUB_TOKEN is not set" && exit 1)
	goreleaser release --clean

## release-snapshot: Create a snapshot release (no git tag required, no GitHub upload)
release-snapshot:
	@echo "Creating snapshot release with GoReleaser..."
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install from https://goreleaser.com/install/" && exit 1)
	goreleaser release --snapshot --clean

## release-dry-run: Dry run of the release process
release-dry-run:
	@echo "Dry run of release process..."
	@which goreleaser > /dev/null || (echo "goreleaser not found. Install from https://goreleaser.com/install/" && exit 1)
	goreleaser release --skip=publish --clean

## run: Build and run the binary
run: build
	$(BUILD_DIR)/$(BINARY_NAME)

## check: Run fmt, vet, and test
check: fmt vet test
	@echo "All checks passed!"
