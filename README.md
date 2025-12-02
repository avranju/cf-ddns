# cf-ddns

`cf-ddns` is a simple tool to update your Cloudflare DNS record with your current public IP address. This is doing pretty much only what I need it to do right now which is to only look at public IPv6 addresses and update the Cloudflare DNS AAAA record if the IP has changed.

## Usage

```bash
cf-ddns
```

## Environment Variables

- `CFDNS_CLOUDFLARE_API_KEY`: Cloudflare API token
- `CFDNS_CLOUDFLARE_ZONE_ID`: Cloudflare zone ID
- `CFDNS_CLOUDFLARE_RECORD_ID`: Cloudflare record ID
- `CFDNS_DOMAIN_NAME`: Domain name (only the record name, not the full domain)
- `CFDNS_PROXIED`: Proxied (default: true)
- `CFDNS_POLL_INTERVAL_SECS`: Poll interval in seconds (default: 300)

## Building

Ensure you have Rust installed from the [official Rust website](https://www.rust-lang.org/tools/install). Then run:

```bash
cargo build --release
```

## Running

Create a `.env` file with the environment variables listed above.

```bash
cargo run --release
```
