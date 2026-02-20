# vulners-proxy-go

[![CI](https://github.com/kidoz/vulners-proxy-go/actions/workflows/ci.yml/badge.svg)](https://github.com/kidoz/vulners-proxy-go/actions/workflows/ci.yml) [![Release](https://github.com/kidoz/vulners-proxy-go/actions/workflows/release.yml/badge.svg)](https://github.com/kidoz/vulners-proxy-go/actions/workflows/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/kidoz/vulners-proxy-go)](https://goreportcard.com/report/github.com/kidoz/vulners-proxy-go) [![GitHub release](https://img.shields.io/github/v/release/kidoz/vulners-proxy-go)](https://github.com/kidoz/vulners-proxy-go/releases) [![License](https://img.shields.io/github/license/kidoz/vulners-proxy-go)](LICENSE)

Drop-in reverse proxy for the [Vulners API](https://vulners.com). Clients that currently call `vulners.com` directly can point at this proxy instead. The proxy injects the API key and forwards requests transparently.

## Features

- Transparent proxying of `/api/v3/*` and `/api/v4/*` endpoints
- API key injection — set once in config or pass per-request via `X-Api-Key` header
- Streaming responses (no buffering)
- Upstream host allowlist (only `vulners.com`)
- Header sanitization — selective whitelist in both directions
- Configurable body size limits and timeouts
- Structured JSON logging via `slog`
- Health check and status endpoints
- Systemd service with security hardening
- `.deb` and `.rpm` packages via GoReleaser

## Quick start

```bash
# Build
go build -o vulners-proxy ./cmd/vulners-proxy

# Edit config — set your API key
cp configs/config.toml myconfig.toml
vim myconfig.toml

# Run
./vulners-proxy --config myconfig.toml

# Test
curl http://localhost:8000/healthz
curl http://localhost:8000/api/v3/search/lucene/?query=cve-2024-1234
```

## Installation

### From packages

Download `.deb` or `.rpm` from the [Releases](../../releases) page.

**Ubuntu / Debian:**

```bash
sudo dpkg -i vulners-proxy_<version>_linux_amd64.deb
sudo vim /etc/vulners-proxy/config.toml   # set api_key
sudo systemctl start vulners-proxy
```

**Rocky Linux / AlmaLinux / RHEL:**

```bash
sudo rpm -i vulners-proxy_<version>_linux_amd64.rpm
sudo vim /etc/vulners-proxy/config.toml   # set api_key
sudo systemctl start vulners-proxy
```

### From source

Requires Go 1.26+.

```bash
go install vulners-proxy-go/cmd/vulners-proxy@latest
```

## Configuration

Configuration is loaded from TOML. The proxy searches for config files in this order:

1. `--config` / `-c` flag or `CONFIG_PATH` env var (explicit path)
2. `/etc/vulners-proxy/config.toml` (system install)
3. `configs/config.toml` (local development)

### Example config

```toml
[server]
host = "0.0.0.0"
port = 8000
body_max_bytes = 10485760        # 10 MB

[vulners]
api_key = ""                     # optional; if empty, clients must send X-Api-Key header

[upstream]
base_url = "https://vulners.com"
timeout_seconds = 120
idle_connections = 100

[log]
level = "info"                   # debug | info | warn | error
format = "json"                  # json | text
```

### CLI flags

All flags override the corresponding config file values.

```
  -c, --config=STRING        Path to TOML config file ($CONFIG_PATH)
      --host=STRING          Listen host ($HOST)
  -p, --port=INT             Listen port ($PORT)
      --api-key=STRING       Vulners API key ($VULNERS_API_KEY)
      --log-level=STRING     Log level: debug|info|warn|error ($LOG_LEVEL)
```

## API key modes

### Mode 1: Shared key in config

Set `api_key` in the config file. All requests use this key — clients don't need to provide one.

```toml
[vulners]
api_key = "YOUR_REAL_API_KEY"
```

### Mode 2: Per-request key via header

Leave `api_key` empty. Clients must send the `X-Api-Key` header with each request.

```bash
curl -H "X-Api-Key: YOUR_REAL_API_KEY" http://localhost:8000/api/v3/search/lucene/?query=test
```

If no key is available from either source, the proxy returns `401 Unauthorized`.

## Endpoints

| Route | Description |
|---|---|
| `ANY /api/v3/*` | Proxied to Vulners API v3 |
| `ANY /api/v4/*` | Proxied to Vulners API v4 |
| `GET /healthz` | Liveness probe — `{"status":"ok"}` |
| `GET /proxy/status` | Version and upstream URL |

All other paths return 404.

## Development

Requires [just](https://github.com/casey/just) (optional) and [golangci-lint](https://golangci-lint.run/).

```bash
just check          # format + lint + test
just build          # build binary
just run            # run with default config
just test           # run tests
just lint           # golangci-lint
just snapshot       # build deb/rpm packages (snapshot)
```

Or without `just`:

```bash
gofmt -w .
golangci-lint run ./...
go test ./...
go build -o vulners-proxy ./cmd/vulners-proxy
```

## Project structure

```
cmd/vulners-proxy/main.go       # Entrypoint, Fx wiring
configs/config.toml              # Default config
internal/
  config/                        # Config loading and validation
  model/                         # Shared types (ProxyRequest, ProxyResponse)
  client/                        # Upstream HTTP client
  service/                       # Core proxy logic (URL build, header filter, key inject)
  handler/                       # Echo HTTP handlers (proxy, health, routes)
  middleware/                    # Request logging, security headers
packaging/
  systemd/                       # Systemd service file
  scripts/                       # deb/rpm install scripts
```

## Building packages

Requires [GoReleaser](https://goreleaser.com/).

```bash
# Snapshot build (no git tag needed)
goreleaser release --snapshot --clean

# Release build (requires git tag)
git tag v1.0.0
goreleaser release --clean
```

Packages are output to `dist/`. Both `amd64` and `arm64` are built.

## Security

- Only `vulners.com` is allowed as an upstream host
- Request headers are filtered to a strict whitelist before forwarding
- Response headers are filtered before returning to the client
- Hop-by-hop headers are stripped
- API keys are never logged
- Body size limits are enforced
- Systemd unit runs with `NoNewPrivileges`, `ProtectSystem=strict`, and other hardening options

## Author and License

**License**: This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Author**: Aleksandr Pavlov (ckidoz@gmail.com)
