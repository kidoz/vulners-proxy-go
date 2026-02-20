# vulners-proxy-go task runner

binary := "vulners-proxy"
cmd    := "./cmd/vulners-proxy"

# List available recipes
default:
    @just --list

# Build the binary
build:
    go build -o {{binary}} {{cmd}}

# Format all Go source files
fmt:
    gofmt -w .

# Run golangci-lint
lint:
    golangci-lint run ./...

# Run all tests
test:
    go test ./...

# Run tests with verbose output
test-v:
    go test -v ./...

# Run tests with race detector
test-race:
    go test -race ./...

# Format, lint, and test
check: fmt lint test

# Run the proxy (requires valid config)
run *ARGS:
    go run {{cmd}} {{ARGS}}

# Tidy module dependencies
tidy:
    go mod tidy

# Build snapshot packages (deb + rpm) without publishing
snapshot:
    goreleaser release --snapshot --clean

# Build release packages (requires git tag)
release:
    goreleaser release --clean

# Clean build artifacts
clean:
    rm -f {{binary}}
    rm -rf dist/
