# cf-ddns

`cf-ddns` is a tool to keep Cloudflare DNS AAAA records in sync with a host's public IPv6 address. It also optionally updates IPv6 traffic matching lists on a UniFi router when the address changes.

## Subcommands

The binary has two subcommands:

```bash
cf-ddns ddns --config config.json   # run the DDNS update loop
cf-ddns ipv6 --output-path <path>   # monitor IPv6 address changes on the host
```

### `ddns`

Polls the host's network interfaces on a configurable interval, and whenever the public IPv6 address changes it:

1. Updates all configured Cloudflare AAAA records
2. Updates any configured UniFi IPv6 traffic matching lists
3. Kicks configured UniFi firewall policies to force them to reload the updated lists

The config file path can also be supplied via the `CFDNS_CONFIG_FILE` environment variable.

### `ipv6`

Intended to run as a systemd service directly on the host (see [Deployment](#deployment) below). It:

1. Writes the current contents of `/proc/net/if_inet6` to `--output-path` on startup
2. Opens a netlink socket and subscribes to IPv6 address change notifications from the kernel
3. On every notification, rewrites the output file and runs `--signal-command` to wake the `ddns` process

```
Options:
  --output-path <PATH>        Path to write the if_inet6 file to
  --signal-command <COMMAND>  Command to signal the ddns process
                              [default: "docker kill --signal SIGUSR1 cf_ddns"]
```

## Configuration

`cf-ddns ddns` requires a JSON configuration file. A full example is provided in `config.example.json`.

```json
{
    "poll_interval_secs": 300,
    "interface": "eth0",
    "if_inet6_path": "/proc/net/if_inet6",
    "cloudflare": {
        "api_key": "your_cloudflare_api_key",
        "zone_id": "your_zone_id",
        "proxied": true,
        "records": [
            {
                "record_id": "record_id_1",
                "domain_name": "example.com"
            }
        ]
    },
    "unifi": {
        "base_url": "https://192.168.1.1",
        "site_id": "your_site_uuid",
        "api_key": "your_unifi_api_key",
        "verify_tls": false,
        "address_ids": ["your_address_list_uuid"],
        "firewall_policy_ids": ["your_firewall_policy_uuid"]
    }
}
```

### Top-level fields

| Field | Default | Description |
|---|---|---|
| `poll_interval_secs` | `300` | How often to check for IP changes |
| `interface` | *(first global non-temporary address found)* | Network interface to read the IPv6 address from |
| `if_inet6_path` | `/proc/net/if_inet6` | Path to read interface IPv6 addresses from. Override this when running in Docker (see [Deployment](#deployment)) |

### `cloudflare`

| Field | Default | Description |
|---|---|---|
| `api_key` | required | Cloudflare API token |
| `zone_id` | required | Cloudflare zone ID |
| `proxied` | `true` | Whether the DNS records should be proxied through Cloudflare |
| `records` | required | List of `{ record_id, domain_name }` AAAA records to update |

### `unifi` (optional)

| Field | Default | Description |
|---|---|---|
| `base_url` | required | Base URL of the UniFi router, e.g. `https://192.168.1.1` |
| `site_id` | required | UniFi site UUID |
| `api_key` | required | UniFi API key |
| `verify_tls` | `false` | Whether to verify the router's TLS certificate |
| `address_ids` | required | List of traffic matching list UUIDs to update with the new IP |
| `firewall_policy_ids` | `[]` | List of firewall policy UUIDs to kick after an address list update. This works around a UniFi bug where firewall rules cache the contents of referenced address lists and need to be touched to pick up changes. |

## Building

Ensure you have Rust installed from the [official Rust website](https://www.rust-lang.org/tools/install).

```bash
cargo build --release
```

## Running locally

```bash
cargo run --release -- ddns --config config.json
```

## Using `just`

A `justfile` is provided for common tasks. Install [`just`](https://github.com/casey/just) and then:

```bash
just build    # cargo build --release
just test     # cargo test
just install  # build, install binary to /usr/local/bin, install systemd unit, reload systemd
just enable   # systemctl enable --now cf-ddns-ipv6.service
just disable  # systemctl disable --now cf-ddns-ipv6.service
```

`just install` and `just enable` will prompt for your sudo password for the steps that need it.

## Deployment

The recommended setup runs two processes:

- **Host** — `cf-ddns ipv6` as a systemd service, with direct access to `/proc/net/if_inet6`
- **Container** — `cf-ddns ddns` in Docker, reading from a file the host process writes

This is necessary because Docker does not allow bind-mounting files from inside `/proc` into a container.

### 1. Install and start the host service

```bash
just install   # installs binary + cf-ddns-ipv6.service, reloads systemd
just enable    # enables and starts the service
```

The service writes the if_inet6 data to `/run/cf-ddns/if_inet6` (the directory is managed automatically by systemd's `RuntimeDirectory`). On every IPv6 address change it runs `docker kill --signal SIGUSR1 cf_ddns` to wake the container immediately.

To use a different signal command, edit `cf-ddns-ipv6.service` and run `just install` again.

### 2. Configure the container

Mount the host-written file into the container at a path outside `/proc`, and point `if_inet6_path` at it.

`docker-compose.yml`:
```yaml
services:
  cf_ddns:
    image: ghcr.io/avranju/cf-ddns:latest
    container_name: cf_ddns
    restart: always
    environment:
      - CFDNS_CONFIG_FILE=/config.json
    volumes:
      - ./config.json:/config.json
      - /run/cf-ddns/if_inet6:/run/if_inet6:ro
```

`config.json`:
```json
{
    "if_inet6_path": "/run/if_inet6",
    ...
}
```

### 3. Start the container

```bash
docker-compose up -d
```
