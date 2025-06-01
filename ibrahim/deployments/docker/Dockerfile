# Builder stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make ca-certificates

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X github.com/ibrahimsql/spiderjs/pkg/version.GitCommit=$(git rev-parse --short HEAD) -X github.com/ibrahimsql/spiderjs/pkg/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o spiderjs cmd/spiderjs/main.go

# Runtime stage
FROM alpine:3.19

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates curl tzdata

# Copy binary from builder stage
COPY --from=builder /app/spiderjs /usr/local/bin/spiderjs

# Copy config files
COPY configs/default.yaml /app/config/config.yaml
COPY configs/ml/model.json /app/configs/ml/model.json

# Create directories for persistent data
RUN mkdir -p /app/data

# Set non-root user
RUN addgroup -g 1000 spiderjs && \
    adduser -u 1000 -G spiderjs -s /bin/sh -D spiderjs && \
    chown -R spiderjs:spiderjs /app

USER spiderjs

# Expose port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["spiderjs"]

# Set default command
CMD ["server", "--config", "/app/config/config.yaml"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/health || exit 1

# Labels
LABEL org.opencontainers.image.title="SpiderJS"
LABEL org.opencontainers.image.description="JavaScript Application Security Scanner"
LABEL org.opencontainers.image.url="https://github.com/ibrahimsql/spiderjs"
LABEL org.opencontainers.image.source="https://github.com/ibrahimsql/spiderjs"
LABEL org.opencontainers.image.vendor="SpiderJS"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="MIT" 