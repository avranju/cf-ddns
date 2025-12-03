# cf-ddns

`cf-ddns` is a simple tool to update your Cloudflare DNS record with your current public IP address. This is doing pretty much only what I need it to do right now which is to only look at public IPv6 addresses and update the Cloudflare DNS AAAA record if the IP has changed.

## Usage

```bash
cf-ddns --config config.json
```

## Configuration

The application requires a JSON configuration file. You can specify the path to the config file using the `--config` argument or the `CFDNS_CONFIG_FILE` environment variable.

Example `config.json`:

```json
{
    "api_key": "your_api_key",
    "zone_id": "your_zone_id",
    "proxied": true,
    "poll_interval_secs": 300,
    "records": [
        {
            "record_id": "record_id_1",
            "domain_name": "example.com"
        },
        {
            "record_id": "record_id_2",
            "domain_name": "sub.example.com"
        }
    ]
}
```

## Building

Ensure you have Rust installed from the [official Rust website](https://www.rust-lang.org/tools/install). Then run:

```bash
cargo build --release
```

## Running

Create a `config.json` file with your settings.

```bash
cargo run --release -- --config config.json
```
