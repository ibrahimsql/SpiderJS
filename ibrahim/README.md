# SpiderJS

[![Go Report Card](https://goreportcard.com/badge/github.com/ibrahimsql/spiderjs)](https://goreportcard.com/report/github.com/ibrahimsql/spiderjs)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ibrahimsql/spiderjs)](go.mod)

SpiderJS is a powerful tool for analyzing and scanning modern JavaScript applications. It can discover frameworks, APIs, and security vulnerabilities in web applications that use JavaScript.

## Features

- **JavaScript Framework Detection**: Automatically detect popular JavaScript frameworks like React, Vue, Angular, and more
- **Bundle Analysis**: Analyze JavaScript bundles to extract dependencies and vulnerabilities
- **API Discovery**: Discover API endpoints used by JavaScript applications
- **Security Scanning**: Identify security vulnerabilities in JavaScript code
- **Web Server**: Built-in web server for easy integration with other tools
- **Machine Learning**: Uses ML to predict vulnerability patterns

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/ibrahimsql/spiderjs.git
cd spiderjs

# Build the binary
go build -o spiderjs_bin ./cmd/spiderjs
```

### Using Docker

```bash
# Build the Docker image
docker build -t spiderjs -f deployments/docker/Dockerfile .

# Run SpiderJS in a container
docker run -p 8080:8080 spiderjs
```

## Usage

SpiderJS can be used in various ways:

### Command Line Interface

```bash
# Show help
./spiderjs_bin --help

# Analyze a website
./spiderjs_bin analyze --url https://example.com

# Scan a website for vulnerabilities
./spiderjs_bin scan --url https://example.com

# Discover JavaScript frameworks and APIs
./spiderjs_bin discover --url https://example.com
```

### Web Server

```bash
# Start the web server
./spiderjs_bin server --host 127.0.0.1 --port 8080
```

Once the server is running, you can access the following endpoints:

- `GET /`: Home page
- `GET /api/version`: Get the version of SpiderJS
- `GET /api/health`: Health check endpoint
- `POST /api/scan`: Scan a website for vulnerabilities
- `POST /api/analyze`: Analyze JavaScript bundles
- `POST /api/discover`: Discover JavaScript frameworks and APIs

## Configuration

SpiderJS can be configured using a YAML file. By default, it looks for the configuration file at `configs/default.yaml`.

```yaml
server:
  host: "127.0.0.1"
  port: 8080

scanner:
  timeout: 30
  user_agent: "SpiderJS/1.0"
  max_depth: 3
  threads: 5

logging:
  level: "info"
  format: "text"
```

## Development

### Prerequisites

- Go 1.21 or higher
- Docker (for containerized development)

### Setup Development Environment

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...
```

### Project Structure

- `cmd/`: Command-line application entry points
- `internal/`: Internal packages
  - `analyzer/`: Framework and bundle analysis
  - `scanner/`: Security scanning
  - `server/`: Web server
  - `ml/`: Machine learning models
  - `utils/`: Utility functions
- `pkg/`: Public API packages
- `configs/`: Configuration files
- `deployments/`: Deployment configurations
  - `docker/`: Docker configurations
  - `kubernetes/`: Kubernetes configurations
  - `helm/`: Helm charts

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 


