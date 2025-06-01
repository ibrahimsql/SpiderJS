#!/bin/bash

# Exit on error
set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Go to root directory
cd "$ROOT_DIR"

# Set version information
GIT_COMMIT=$(git rev-parse HEAD)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION=$(grep -oP 'Version = "\K[^"]+' pkg/version/version.go)

echo "Building SpiderJS v$VERSION ($GIT_COMMIT) built on $BUILD_DATE"

# Build binary
go build -ldflags "-X github.com/ibrahimsql/spiderjs/pkg/version.GitCommit=$GIT_COMMIT -X github.com/ibrahimsql/spiderjs/pkg/version.BuildDate=$BUILD_DATE" -o spiderjs ./cmd/spiderjs

echo "Build complete: $(pwd)/spiderjs"

# Make executable
chmod +x spiderjs

# Show version
./spiderjs version 