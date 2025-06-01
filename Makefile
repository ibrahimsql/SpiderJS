.PHONY: all build clean test lint vet fmt help

# Binary name
BINARY_NAME=spiderjs

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOVET=$(GOCMD) vet
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-X github.com/ibrahimsql/spiderjs/pkg/version.GitCommit=`git rev-parse HEAD` -X github.com/ibrahimsql/spiderjs/pkg/version.BuildDate=`date -u +%Y-%m-%dT%H:%M:%SZ`"

# Main package path
MAIN_PACKAGE=./cmd/spiderjs

# Default target
all: test build

# Build the binary
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PACKAGE)

# Clean build files
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out

# Run linter
lint:
	golangci-lint run ./...

# Run go vet
vet:
	$(GOVET) ./...

# Format code
fmt:
	$(GOFMT) ./...

# Install dependencies
deps:
	$(GOGET) -v -t ./...

# Install the binary
install:
	$(GOCMD) install $(LDFLAGS) $(MAIN_PACKAGE)

# Build for all platforms
build-all:
	# Linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)
	
	# macOS
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)
	
	# Windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)

# Run the binary
run:
	./$(BINARY_NAME)

# Show help
help:
	@echo "Available targets:"
	@echo "  all           - Run tests and build binary"
	@echo "  build         - Build binary"
	@echo "  clean         - Clean build files"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linter"
	@echo "  vet           - Run go vet"
	@echo "  fmt           - Format code"
	@echo "  deps          - Install dependencies"
	@echo "  install       - Install binary"
	@echo "  build-all     - Build for all platforms"
	@echo "  run           - Run binary"
	@echo "  help          - Show this help" 