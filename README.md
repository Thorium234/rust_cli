# Web Security Auditor

A Rust command-line tool for authorized, defensive web application audits.

This project is a safe implementation derived from the ideas in `task.md`, but it intentionally excludes offensive or harmful capabilities such as:
- authorization bypass attempts
- arbitrary database query execution
- remote file modification
- exploitation workflows

Instead, it focuses on low-risk checks that are appropriate for authorized assessments and learning:
- TCP port reachability checks on specified ports
- base URL probing and HTTP fingerprinting
- security header inspection
- public path probing for common routes and metadata files
- visible rate-limiting detection through repeated requests

## Features

### `audit`
Runs the full defensive audit workflow against an authorized target:
- probes selected TCP ports
- requests the base URL and reports server/header metadata
- checks common public paths such as `/login`, `/admin`, `/robots.txt`, and `/sitemap.xml`
- performs a light rate-limit probe and reports `429`, `Retry-After`, and `X-RateLimit-Remaining` indicators

### `ports`
Checks whether specific TCP ports are reachable on a host.

### `web`
Performs HTTP-focused checks without TCP port scanning.

### `rate`
Sends repeated requests to detect visible rate-limiting behavior.

## Project Structure

- `src/main.rs`: CLI parsing and command orchestration
- `src/scanner.rs`: TCP connect checks and HTTP header inspection
- `src/file.rs`: safe public path probing
- `src/rate_limit.rs`: repeated-request rate-limit detection
- `src/report.rs`: terminal output formatting

## Requirements

- Rust 1.75+ recommended
- network access to the target system
- authorization to assess the target

## Build

```bash
cargo build
```

## Usage

Run a full audit:

```bash
cargo run -- audit https://example.com --host example.com --ports 80,443,8080 --paths /login,/admin,/api/health --rate-requests 8
```

Port-only checks:

```bash
cargo run -- ports example.com --ports 80,443,8443
```

HTTP checks only:

```bash
cargo run -- web https://example.com --paths /,/login,/robots.txt
```

Rate-limit probe:

```bash
cargo run -- rate https://example.com --requests 10
```

## Notes

- The tool performs basic, transparent checks and prints educational output.
- A `200`, `401`, or `403` on a public path can still be useful because it confirms route exposure without attempting bypasses.
- Rate-limiting detection is heuristic. Some systems enforce limits per IP, token, or time window in ways this lightweight probe may not trigger.

## Safety Scope

This repository does not implement exploit development or unauthorized access techniques. Use it only for systems you own or are explicitly permitted to assess.
