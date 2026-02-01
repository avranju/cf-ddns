# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

```bash
cargo build --release          # Build release binary
cargo run --release -- --config config.json  # Run with config file
```

## Architecture

This is a single-binary async Rust application that monitors public IPv6 address changes and updates external services accordingly.

### Main Loop (`main.rs`)

The application runs in a polling loop using `tokio::select!` to handle:
- Periodic IP checks (configurable via `poll_interval_secs`)
- SIGTERM/SIGINT for graceful shutdown
- SIGUSR1 for immediate IP check trigger

### Core Flow (`run_once`)

1. Fetches current public IPv6 from `ifconfig.co/json`
2. Compares against cached IPs for each configured service
3. Updates Cloudflare DNS AAAA records if changed
4. Updates UniFi traffic matching lists if configured and changed

### External Integrations

- **Cloudflare**: Uses the `cloudflare` crate for DNS record updates
- **UniFi**: Direct REST API calls via `reqwest` to `/proxy/network/integration/v1/sites/{site_id}/traffic-matching-lists/{list_id}`

### Caching

Both Cloudflare record IPs and UniFi list IPs are cached in-memory (`HashMap<String, Ipv6Addr>`) to avoid redundant API calls when the IP hasn't changed.

## Configuration Structure

Config is JSON with nested sections:
- `poll_interval_secs`: Top-level polling interval
- `cloudflare`: Required - API key, zone ID, and DNS records to update
- `unifi`: Optional - Router base URL, site ID, API key, and address list IDs

See `config.example.json` for the full schema.
