<p align="center">
  <strong>SafeGate</strong><br>
  A high-performance file security scanning microservice written in Go.
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api-reference">API</a> •
  <a href="#security">Security</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#laravel-integration">Laravel Integration</a> •
  <a href="#license">License</a>
</p>

---

## Overview

SafeGate is a dedicated file security scanning microservice that inspects uploaded files for malware, embedded scripts, file type spoofing, zip bombs, and other threats — **before** they reach your application's storage. It exposes a simple REST API and is designed to sit between your application (e.g. Laravel, Django, Express) and your file storage layer.

## Features

- **Antivirus Scanning** — ClamAV integration via TCP INSTREAM protocol
- **MIME Type Validation** — Detects file type spoofing by comparing magic bytes against claimed MIME types
- **Executable Detection** — Identifies PE (Windows), ELF (Linux), and Mach-O (macOS) binaries disguised as other file types
- **SVG XSS Protection** — Scans SVG files for `<script>` tags, event handlers, `javascript:` URIs, `<foreignObject>`, external references, and embedded base64 payloads
- **Office Macro Detection** — Detects VBA macros, auto-execute triggers, and shell commands in legacy (`.doc`, `.xls`, `.ppt`) and modern (`.docx`, `.xlsx`, `.pptx`) Office formats
- **PDF Security Analysis** — Flags embedded JavaScript, auto-execute actions, launch actions, embedded files, and encrypted streams in PDFs
- **Zip Bomb Protection** — Analyzes compression ratios, nesting depth, decompressed size limits, and detects path traversal in archives
- **Metadata Validation** — Checks file size limits, empty files, null byte injection in text files, filename length, and double-extension spoofing (e.g. `report.pdf.exe`)
- **API Key Authentication** — Optional `X-API-Key` or `Bearer` token authentication with constant-time comparison
- **Security Headers** — X-Content-Type-Options, X-Frame-Options, HSTS, CSP, Referrer-Policy, Permissions-Policy
- **Rate Limiting** — Per-IP token bucket rate limiter with configurable requests/minute
- **CORS Hardening** — Configurable allowed origins (no wildcard by default)
- **Request Timeouts** — Server read/write/idle timeouts + per-request context deadline to prevent slow loris attacks
- **Request Tracing** — Unique `X-Request-ID` header on every response for audit trails and debugging
- **Health Check Endpoint** — Public `/health` endpoint (bypasses auth) for load balancer readiness probes
- **Zero Dependencies Runtime** — Single static binary, runs on Alpine Linux

## Architecture

```
┌──────────────┐       POST /api/v1/scan       ┌────────────────────────┐
│  Your App    │  ──────────────────────────▶   │       SafeGate         │
│  (Laravel,   │                                │                        │
│   Django,    │       JSON response            │  ┌──────────────────┐  │
│   Express)   │  ◀──────────────────────────   │  │ Scanner Pipeline │  │
└──────────────┘                                │  │                  │  │
                                                │  │ 1. Metadata      │  │
                                                │  │ 2. MIME Type     │  │
                                                │  │ 3. SVG XSS      │  │     ┌──────────┐
                                                │  │ 4. Macro/Script  │  │     │  ClamAV  │
                                                │  │ 5. Archive Bomb  │  │     │  Daemon  │
                                                │  │ 6. ClamAV ───────│──│────▶│ (TCP)    │
                                                │  └──────────────────┘  │     └──────────┘
                                                └────────────────────────┘
```

Files are scanned through a **pipeline of 6 scanners** in sequence. If any scanner reports a **critical**, **high**, or **medium** severity finding, the file is marked as **unsafe**.

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/YourName/safegate.git
cd safegate

# Copy and configure environment variables
cp .env.example .env
# Edit .env to set your SAFEGATE_API_KEY

# Start SafeGate + ClamAV
docker compose up -d

# Test the health endpoint
curl http://localhost:8443/health
```

> **Note:** ClamAV takes ~2 minutes on first start to download virus definitions.

### Using Go Directly

```bash
# Prerequisites: Go 1.22+

# Clone and build
git clone https://github.com/YourName/safegate.git
cd safegate
go build -o safegate ./cmd/safegate

# Configure (optional)
export SAFEGATE_PORT=8443
export SAFEGATE_CLAMAV_ENABLED=false  # Set to true if ClamAV is available

# Run
./safegate
```

## API Reference

### Health Check

```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "safegate",
  "time": "2026-03-08T03:43:06Z"
}
```

### Scan File

```
POST /api/v1/scan
Content-Type: multipart/form-data
X-API-Key: your-api-key
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | `multipart` | **Required.** The file to scan. |

**Success Response** (`200 OK` — file is safe):
```json
{
  "success": true,
  "message": "File scan complete — file is safe",
  "data": {
    "safe": true,
    "filename": "report.pdf",
    "file_size": 102400,
    "mime_type": "application/pdf",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
    "scanned_at": "2026-03-08T03:43:06Z",
    "duration_ms": 45,
    "findings": [],
    "scanners_run": [
      "metadata_scanner",
      "mime_type_validator",
      "svg_xss_scanner",
      "macro_script_scanner",
      "archive_bomb_scanner",
      "clamav_antivirus"
    ]
  }
}
```

**Threat Detected Response** (`422 Unprocessable Entity`):
```json
{
  "success": false,
  "message": "File scan complete — threats detected",
  "data": {
    "safe": false,
    "filename": "malicious.svg",
    "file_size": 2048,
    "mime_type": "image/svg+xml",
    "sha256": "a1b2c3d4...",
    "scanned_at": "2026-03-08T03:43:06Z",
    "duration_ms": 12,
    "findings": [
      {
        "scanner": "svg_xss_scanner",
        "severity": "critical",
        "description": "SVG contains <script> tags",
        "details": "Inline JavaScript in SVG files can execute XSS attacks when rendered in a browser"
      }
    ],
    "scanners_run": ["metadata_scanner", "mime_type_validator", "svg_xss_scanner", "macro_script_scanner", "archive_bomb_scanner"]
  }
}
```

**Authentication Error** (`401 Unauthorized`):
```json
{
  "success": false,
  "message": "Invalid or missing API key"
}
```

**Rate Limit Exceeded** (`429 Too Many Requests`):
```json
{
  "success": false,
  "message": "Rate limit exceeded. Try again later."
}
```

> **Note:** All responses include `X-Request-ID` and security headers. See the [Security](#security) section for details.

### cURL Examples

```bash
# Scan a file
curl -X POST http://localhost:8443/api/v1/scan \
  -H "X-API-Key: your-secret-api-key" \
  -F "file=@document.pdf"

# Using Bearer token authentication
curl -X POST http://localhost:8443/api/v1/scan \
  -H "Authorization: Bearer your-secret-api-key" \
  -F "file=@photo.jpg"
```

## Security

SafeGate follows security best practices for API services. All security features are configurable via environment variables.

### Security Headers

Every response includes the following headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `X-XSS-Protection` | `0` | Defers to CSP (modern best practice) |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Enforces HTTPS for 2 years |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Blocks all content loading |
| `Referrer-Policy` | `no-referrer` | Prevents referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disables browser features |
| `Cache-Control` | `no-store` | Prevents caching of scan results |

### Request Tracing

Every response includes an `X-Request-ID` header containing a cryptographically random 32-character hex string. This ID is also logged with the request for correlation and audit trails.

### Rate Limiting

Per-IP token bucket rate limiting is enabled by default at **60 requests/minute**. When exceeded, the API returns `429 Too Many Requests` with a `Retry-After: 60` header. Configure via `SAFEGATE_RATE_LIMIT_RPM` (set to `0` to disable).

### CORS

CORS is **restrictive by default** — no cross-origin requests are allowed unless you explicitly set `SAFEGATE_CORS_ORIGINS`. Set specific origins for production:

```bash
SAFEGATE_CORS_ORIGINS=https://app.example.com,https://admin.example.com
```

### Server Timeouts

To prevent slow loris and resource exhaustion attacks:

| Timeout | Default | Purpose |
|---------|---------|---------|
| Read | 30s | Max time to read the full request |
| Write | 60s | Max time to write the full response |
| Idle | 120s | Max time for keep-alive connections |
| Request | 300s | Per-request context deadline (for large file scans) |

### API Key Best Practices

- Use a cryptographically random key of **at least 32 characters**
- SafeGate warns on startup if the key is missing or too short
- Authentication uses **constant-time comparison** to prevent timing attacks
- The `/health` endpoint is public and does **not** require authentication

### Trusted Proxies

If SafeGate sits behind a reverse proxy (nginx, Cloudflare, AWS ALB), configure trusted proxy IPs so rate limiting uses the real client IP:

```bash
SAFEGATE_TRUSTED_PROXIES=10.0.0.1,172.16.0.1
```

Only `X-Forwarded-For` and `X-Real-IP` headers from trusted proxy IPs are respected.

## Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` to get started.

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFEGATE_PORT` | `8443` | HTTP server port |
| `SAFEGATE_API_KEY` | *(empty)* | API key for authentication (min 32 chars recommended). Leave empty to disable auth. |
| `SAFEGATE_MAX_FILE_SIZE` | `52428800` (50 MB) | Maximum upload file size in bytes |
| `SAFEGATE_CLAMAV_ADDR` | `clamav:3310` | ClamAV daemon TCP address |
| `SAFEGATE_CLAMAV_ENABLED` | `true` | Enable/disable ClamAV antivirus scanning |
| `SAFEGATE_MAX_ARCHIVE_DEPTH` | `3` | Maximum archive nesting depth (zip bomb protection) |
| `SAFEGATE_MAX_ARCHIVE_SIZE` | `209715200` (200 MB) | Maximum decompressed archive size in bytes |
| `SAFEGATE_ALLOWED_TYPES` | *(see below)* | Comma-separated list of allowed MIME types |
| `SAFEGATE_TEMP_DIR` | OS temp dir | Temporary directory for file processing |
| `SAFEGATE_CORS_ORIGINS` | *(empty)* | Comma-separated allowed CORS origins (empty = block cross-origin) |
| `SAFEGATE_RATE_LIMIT_RPM` | `60` | Max requests per minute per IP (0 = disabled) |
| `SAFEGATE_READ_TIMEOUT` | `30` | HTTP server read timeout in seconds |
| `SAFEGATE_WRITE_TIMEOUT` | `60` | HTTP server write timeout in seconds |
| `SAFEGATE_IDLE_TIMEOUT` | `120` | HTTP server idle timeout in seconds |
| `SAFEGATE_REQUEST_TIMEOUT` | `300` | Per-request context timeout in seconds |
| `SAFEGATE_TRUSTED_PROXIES` | *(empty)* | Comma-separated trusted proxy IPs for X-Forwarded-For |

### Default Allowed MIME Types

```
application/pdf, application/msword,
application/vnd.openxmlformats-officedocument.wordprocessingml.document,
application/vnd.ms-excel,
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,
application/vnd.ms-powerpoint,
application/vnd.openxmlformats-officedocument.presentationml.presentation,
image/jpeg, image/png, image/gif, image/webp, image/svg+xml,
application/zip, application/x-rar-compressed, application/x-7z-compressed,
text/plain, text/csv, application/json
```

## Scanner Pipeline

SafeGate runs files through a pipeline of scanners in order. Each scanner implements the `Scanner` interface and returns findings with severity levels.

| Scanner | What It Detects |
|---------|----------------|
| **Metadata Scanner** | File size violations, empty files, null byte injection, filename length, double-extension spoofing |
| **MIME Type Validator** | Disallowed file types, MIME type spoofing (magic bytes vs. claimed type), hidden executables |
| **SVG XSS Scanner** | `<script>` tags, event handlers (`onload`, `onclick`), `javascript:` URIs, `data:` URIs, `<foreignObject>`, external `xlink:href`, embedded base64 |
| **Macro/Script Scanner** | PDF JavaScript/auto-actions/launch actions, Office VBA macros, auto-execute macros (`AutoOpen`, `Document_Open`), shell commands, external template references |
| **Archive Bomb Scanner** | Zip bombs (compression ratio >100:1), excessive nesting depth, decompressed size limits, path traversal (`..`), executables inside archives, excessive file count (>10,000) |
| **ClamAV Antivirus** | Malware, viruses, trojans, and other threats via ClamAV virus definitions |

### Severity Levels

| Level | Effect | Description |
|-------|--------|-------------|
| `critical` | File rejected | Confirmed threat (malware, XSS, executable disguise) |
| `high` | File rejected | Likely threat (type spoofing, suspicious macros) |
| `medium` | File rejected | Possible threat (encrypted streams, null bytes) |
| `low` | File accepted | Informational warning (empty file, URI actions in PDF) |
| `info` | File accepted | Informational note |

## Laravel Integration

### Using Guzzle HTTP Client

```php
<?php

namespace App\Services;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Http;

class SafeGateService
{
    public function scan(UploadedFile $file): array
    {
        $response = Http::withHeaders([
            'X-API-Key' => config('services.safegate.api_key'),
        ])->attach(
            'file',
            file_get_contents($file->getRealPath()),
            $file->getClientOriginalName()
        )->post(config('services.safegate.url') . '/api/v1/scan');

        return $response->json();
    }

    public function isSafe(UploadedFile $file): bool
    {
        $result = $this->scan($file);
        return $result['success'] ?? false;
    }
}
```

### Laravel Config (`config/services.php`)

```php
'safegate' => [
    'url' => env('SAFEGATE_URL', 'http://localhost:8443'),
    'api_key' => env('SAFEGATE_API_KEY'),
],
```

### Usage in a Controller

```php
public function upload(Request $request, SafeGateService $scanner)
{
    $request->validate(['file' => 'required|file|max:51200']);

    $file = $request->file('file');
    $result = $scanner->scan($file);

    if (!$result['success']) {
        return response()->json([
            'message' => 'File rejected — security threats detected.',
            'findings' => $result['data']['findings'] ?? [],
        ], 422);
    }

    // File is safe — proceed with storage
    $path = $file->store('uploads', 'public');

    return response()->json([
        'message' => 'File uploaded successfully.',
        'path' => $path,
        'scan' => $result['data'],
    ]);
}
```

## Project Structure

```
safegate/
├── cmd/
│   └── safegate/
│       └── main.go              # Application entry point, wiring
├── internal/
│   ├── config/
│   │   └── config.go            # Environment-based configuration
│   ├── handler/
│   │   └── handler.go           # HTTP handlers (scan + health)
│   ├── middleware/
│   │   └── middleware.go         # Auth, security headers, rate limiting, CORS, request ID, logging
│   └── scanner/
│       ├── scanner.go           # Scanner interface, orchestrator, types
│       ├── metadata.go          # File metadata validation
│       ├── mime.go              # MIME type detection and spoofing checks
│       ├── svg.go               # SVG XSS attack detection
│       ├── macro.go             # Office macro and PDF script detection
│       ├── archive.go           # Zip bomb and archive analysis
│       └── clamav.go            # ClamAV TCP integration
├── .env.example                 # Example environment configuration
├── Dockerfile                   # Multi-stage build (Go → Alpine)
├── docker-compose.yml           # SafeGate + ClamAV stack
├── go.mod
├── go.sum
└── LICENSE                      # Apache 2.0
```

## License

SafeGate is licensed under the [Apache License 2.0](LICENSE).
