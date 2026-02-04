use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::Ipv6Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use cloudflare::{
    endpoints::dns::dns,
    framework::{Environment, auth::Credentials, client::async_api::Client as CfClient},
};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use tokio::{signal, time};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about = "Cloudflare DDNS", long_about = None)]
struct Args {
    /// Path to the JSON configuration file
    #[arg(short, long, env = "CFDNS_CONFIG_FILE")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Optional network interface name to get IPv6 address from.
    /// If not specified, uses the first global non-temporary IPv6 address found.
    pub interface: Option<String>,
    pub cloudflare: CloudflareConfig,
    pub unifi: Option<UnifiConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareConfig {
    pub api_key: String,
    pub zone_id: String,
    #[serde(default = "default_proxied")]
    pub proxied: bool,
    pub records: Vec<RecordConfig>,
}

#[derive(Debug, Deserialize)]
pub struct UnifiConfig {
    pub base_url: String,
    pub site_id: String,
    pub api_key: String,
    #[serde(default = "default_verify_tls")]
    pub verify_tls: bool,
    pub address_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnifiTrafficMatchingList {
    #[serde(rename = "type")]
    pub list_type: String,
    pub id: String,
    pub name: String,
    pub items: Vec<UnifiAddressItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnifiAddressItem {
    #[serde(rename = "type")]
    pub item_type: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
struct UnifiUpdateRequest {
    #[serde(rename = "type")]
    list_type: String,
    name: String,
    items: Vec<UnifiAddressItem>,
}

#[derive(Debug, Deserialize)]
pub struct RecordConfig {
    pub record_id: String,
    pub domain_name: String,
}

fn default_proxied() -> bool {
    true
}

fn default_poll_interval() -> u64 {
    300
}

fn default_verify_tls() -> bool {
    false
}


#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    // Initialize tracing subscriber for logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");

    let args = Args::parse();

    // Load configuration
    let file = File::open(&args.config).context("Failed to open config file")?;
    let reader = BufReader::new(file);
    let config: Config = serde_json::from_reader(reader).context("Failed to parse config file")?;

    let credentials = Credentials::UserAuthToken {
        token: config.cloudflare.api_key.clone(),
    };
    let cf_client = CfClient::new(credentials, Default::default(), Environment::Production)?;

    // Create UniFi HTTP client if configured
    let unifi_client = if let Some(ref unifi_config) = config.unifi {
        let client = HttpClient::builder()
            .danger_accept_invalid_certs(!unifi_config.verify_tls)
            .build()?;
        Some(client)
    } else {
        None
    };

    let mut interval = time::interval(time::Duration::from_secs(config.poll_interval_secs));

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;

    // Cache for Cloudflare record IP to avoid redundant API calls
    // Map record_id -> Ipv6Addr
    let mut cf_ip_cache: HashMap<String, Ipv6Addr> = HashMap::new();

    // Cache for UniFi address list IP to avoid redundant API calls
    // Map list_id -> Ipv6Addr
    let mut unifi_ip_cache: HashMap<String, Ipv6Addr> = HashMap::new();

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, exiting");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT, exiting");
                break;
            }
            _ = interval.tick() => {
                match run_once(&config, &cf_client, &mut cf_ip_cache, unifi_client.as_ref(), &mut unifi_ip_cache).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("Run failed: {e}");
                    }
                }
            }
            _ = sigusr1.recv() => {
                tracing::info!("Received SIGUSR1, running update check");
                match run_once(&config, &cf_client, &mut cf_ip_cache, unifi_client.as_ref(), &mut unifi_ip_cache).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("Run failed: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_once(
    config: &Config,
    cf_client: &CfClient,
    cf_cache: &mut HashMap<String, Ipv6Addr>,
    unifi_client: Option<&HttpClient>,
    unifi_cache: &mut HashMap<String, Ipv6Addr>,
) -> Result<()> {
    // get current public ip from local network interfaces
    let ip = find_local_ipv6(config.interface.as_deref())?;

    // Update Cloudflare DNS records
    let cf_config = &config.cloudflare;
    for record in &cf_config.records {
        let record_id = &record.record_id;

        // get current cloudflare record ip (from cache if available)
        let record_ip = if let Some(cached_ip) = cf_cache.get(record_id) {
            tracing::debug!(
                "Using cached Cloudflare IP for {}: {cached_ip}",
                record.domain_name
            );
            *cached_ip
        } else {
            let ip = find_cf_record_ip(cf_client, &cf_config.zone_id, record_id).await?;
            tracing::debug!(
                "Retrieved Cloudflare IP from API for {}: {ip}",
                record.domain_name
            );
            cf_cache.insert(record_id.clone(), ip);
            ip
        };

        // if ip has changed, update cloudflare record
        if ip != record_ip {
            update_cf_record(cf_config, record, cf_client, ip, cf_cache).await?;
            tracing::info!("Updated Cloudflare IP for {} to {ip}", record.domain_name);
        } else {
            tracing::info!("Cloudflare IP {ip} for {} has not changed", record.domain_name);
        }
    }

    // Update UniFi address lists if configured
    if let (Some(unifi_config), Some(http_client)) = (&config.unifi, unifi_client) {
        for list_id in &unifi_config.address_ids {
            // Check cache first
            let cached_ip = unifi_cache.get(list_id).copied();
            let needs_update = cached_ip.map(|cached| cached != ip).unwrap_or(true);

            if needs_update {
                match update_unifi_address_list(http_client, unifi_config, list_id, ip, unifi_cache)
                    .await
                {
                    Ok(()) => {
                        tracing::info!("Updated UniFi address list {list_id} to {ip}");
                    }
                    Err(e) => {
                        tracing::error!("Failed to update UniFi address list {list_id}: {e}");
                    }
                }
            } else {
                tracing::info!("UniFi address list {list_id} IP {ip} has not changed");
            }
        }
    }

    Ok(())
}

async fn update_cf_record(
    config: &CloudflareConfig,
    record: &RecordConfig,
    client: &CfClient,
    ip: Ipv6Addr,
    cache: &mut HashMap<String, Ipv6Addr>,
) -> Result<()> {
    let endpoint = dns::UpdateDnsRecord {
        zone_identifier: &config.zone_id,
        identifier: &record.record_id,
        params: dns::UpdateDnsRecordParams {
            content: dns::DnsContent::AAAA { content: ip },
            proxied: Some(config.proxied),
            ttl: None,
            name: &record.domain_name,
        },
    };

    let _ = client.request(&endpoint).await?;

    // Update cache with the new IP after successful update
    cache.insert(record.record_id.clone(), ip);

    Ok(())
}

/// Parses IPv6 addresses from /proc/net/if_inet6 content.
///
/// The format is: address device_index prefix_len scope flags interface_name
///
/// Only returns addresses where:
/// - scope is 0x00 (global)
/// - IFA_F_TEMPORARY flag (0x01) is NOT set
fn parse_ipv6_from_proc_content(content: &str, interface_filter: Option<&str>) -> Result<Ipv6Addr> {
    const IFA_F_TEMPORARY: u8 = 0x01;
    const SCOPE_GLOBAL: u8 = 0x00;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let addr_hex = parts[0];
        let scope = u8::from_str_radix(parts[3], 16).unwrap_or(0xff);
        let flags = u8::from_str_radix(parts[4], 16).unwrap_or(0);
        let iface = parts[5];

        // Filter by interface if specified
        if let Some(filter) = interface_filter {
            if iface != filter {
                continue;
            }
        }

        // Check for global scope
        if scope != SCOPE_GLOBAL {
            continue;
        }

        // Exclude temporary addresses (privacy extensions)
        if flags & IFA_F_TEMPORARY != 0 {
            continue;
        }

        // Parse the IPv6 address from compact hex format
        if addr_hex.len() != 32 {
            continue;
        }

        let mut segments = [0u16; 8];
        let mut valid = true;
        for (i, segment) in segments.iter_mut().enumerate() {
            let start = i * 4;
            match u16::from_str_radix(&addr_hex[start..start + 4], 16) {
                Ok(v) => *segment = v,
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }

        if !valid {
            continue;
        }

        let addr = Ipv6Addr::from(segments);
        tracing::debug!("Found global IPv6 address {addr} on interface {iface}");
        return Ok(addr);
    }

    Err(anyhow::anyhow!(
        "No suitable global non-temporary IPv6 address found{}",
        interface_filter
            .map(|i| format!(" on interface {i}"))
            .unwrap_or_default()
    ))
}

/// Finds a global, non-temporary IPv6 address from local network interfaces.
///
/// Reads from /proc/net/if_inet6 and parses the content to find suitable addresses.
fn find_local_ipv6(interface_filter: Option<&str>) -> Result<Ipv6Addr> {
    let content = fs::read_to_string("/proc/net/if_inet6")
        .context("Failed to read /proc/net/if_inet6")?;
    
    parse_ipv6_from_proc_content(&content, interface_filter)
}

async fn find_cf_record_ip(
    client: &CfClient,
    zone_identifier: &str,
    record_id: &str,
) -> Result<Ipv6Addr> {
    let endpoint = dns::ListDnsRecords {
        zone_identifier,
        params: Default::default(),
    };

    let response = client.request(&endpoint).await?;
    let record = response
        .result
        .iter()
        .find(|v| v.id == record_id)
        .ok_or_else(|| anyhow::anyhow!("Record not found"))?;

    match &record.content {
        dns::DnsContent::AAAA { content } => Ok(*content),
        _ => Err(anyhow::anyhow!("Unsupported record type")),
    }
}

async fn get_unifi_address_list(
    http_client: &HttpClient,
    config: &UnifiConfig,
    list_id: &str,
) -> Result<UnifiTrafficMatchingList> {
    let url = format!(
        "{}/proxy/network/integration/v1/sites/{}/traffic-matching-lists/{}",
        config.base_url, config.site_id, list_id
    );

    let resp = http_client
        .get(&url)
        .header("X-API-KEY", &config.api_key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?;

    let list: UnifiTrafficMatchingList = resp.json().await?;
    Ok(list)
}

async fn update_unifi_address_list(
    http_client: &HttpClient,
    config: &UnifiConfig,
    list_id: &str,
    ip: Ipv6Addr,
    cache: &mut HashMap<String, Ipv6Addr>,
) -> Result<()> {
    // First, get the current list to preserve the name
    let current = get_unifi_address_list(http_client, config, list_id).await?;

    let url = format!(
        "{}/proxy/network/integration/v1/sites/{}/traffic-matching-lists/{}",
        config.base_url, config.site_id, list_id
    );

    let request_body = UnifiUpdateRequest {
        list_type: "IPV6_ADDRESSES".to_string(),
        name: current.name,
        items: vec![UnifiAddressItem {
            item_type: "IP_ADDRESS".to_string(),
            value: ip.to_string(),
        }],
    };

    http_client
        .put(&url)
        .header("X-API-KEY", &config.api_key)
        .header("Accept", "application/json")
        .json(&request_body)
        .send()
        .await?
        .error_for_status()?;

    // Update cache after successful update
    cache.insert(list_id.to_string(), ip);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv6_from_proc_content_single_address() {
        let content = "fe80000000000000020c29fffe123456 02 40 20 80 eth0\n\
                       20010db8000000000000000000000001 01 40 00 80 eth0";
        
        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_with_interface_filter() {
        let content = "20010db8000000000000000000000001 01 40 00 80 eth0\n\
                       20010db8000000000000000000000002 01 40 00 80 eth1";
        
        let result = parse_ipv6_from_proc_content(content, Some("eth1"));
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.to_string(), "2001:db8::2");
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_excludes_temporary() {
        let content = "20010db8000000000000000000000001 01 40 00 81 eth0\n\
                       20010db8000000000000000000000002 01 40 00 80 eth0";
        
        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.to_string(), "2001:db8::2");
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_excludes_non_global() {
        let content = "20010db8000000000000000000000001 01 40 20 80 eth0\n\
                       20010db8000000000000000000000002 01 40 00 80 eth0";
        
        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.to_string(), "2001:db8::2");
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_no_valid_address() {
        let content = "fe80000000000000020c29fffe123456 02 40 20 80 eth0\n\
                       20010db8000000000000000000000001 01 40 20 80 eth0";
        
        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No suitable global non-temporary IPv6 address found"));
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_empty_content() {
        let content = "";
        
        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No suitable global non-temporary IPv6 address found"));
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_malformed_lines() {
        let content = "invalid_line\n\
                       20010db8000000000000000000000001 01 40 00 80 eth0";
        
        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_interface_not_found() {
        let content = "20010db8000000000000000000000001 01 40 00 80 eth0";
        
        let result = parse_ipv6_from_proc_content(content, Some("eth1"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No suitable global non-temporary IPv6 address found on interface eth1"));
    }
}
