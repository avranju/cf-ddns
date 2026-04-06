use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Local;
use clap::{Parser, Subcommand};
use netlink_sys::{AsyncSocket, AsyncSocketExt, TokioSocket, protocols::NETLINK_ROUTE};
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
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the DDNS update loop
    Ddns {
        /// Path to the JSON configuration file
        #[arg(short, long, env = "CFDNS_CONFIG_FILE")]
        config: PathBuf,
    },
    /// Monitor host IPv6 address changes via netlink and write the if_inet6 file
    Ipv6 {
        /// Path to write the if_inet6 file to
        #[arg(long)]
        output_path: PathBuf,

        /// Shell command to run to signal the ddns process after a change
        #[arg(long, default_value = "docker kill --signal SIGUSR1 cf_ddns")]
        signal_command: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Optional network interface name to get IPv6 address from.
    /// If not specified, uses the first global non-temporary IPv6 address found.
    pub interface: Option<String>,
    /// Path to read the if_inet6 file from. Defaults to /proc/net/if_inet6.
    /// Override when the file is volume-mounted into the container at a different path.
    #[serde(default = "default_if_inet6_path")]
    pub if_inet6_path: String,
    pub cloudflare: Vec<CloudflareZoneConfig>,
    pub unifi: Option<UnifiConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareZoneConfig {
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
    /// IDs of firewall policies to "kick" (update description with a timestamp)
    /// after an address list update, to force the firewall to re-evaluate rules.
    #[serde(default)]
    pub firewall_policy_ids: Vec<String>,
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

fn default_if_inet6_path() -> String {
    "/proc/net/if_inet6".to_string()
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

    match args.command {
        Command::Ipv6 { output_path, signal_command } => {
            run_ipv6_mode(output_path, signal_command).await?;
        }
        Command::Ddns { config: config_path } => {

            // Load configuration
            let file = File::open(&config_path).context("Failed to open config file")?;
            let reader = BufReader::new(file);
            let config: Config =
                serde_json::from_reader(reader).context("Failed to parse config file")?;

            let cf_clients: Vec<CfClient> = config
                .cloudflare
                .iter()
                .map(|zone| {
                    let credentials = Credentials::UserAuthToken {
                        token: zone.api_key.clone(),
                    };
                    CfClient::new(credentials, Default::default(), Environment::Production)
                        .map_err(anyhow::Error::from)
                })
                .collect::<Result<_>>()?;

            // Create UniFi HTTP client if configured
            let unifi_client = if let Some(ref unifi_config) = config.unifi {
                let client = HttpClient::builder()
                    .danger_accept_invalid_certs(!unifi_config.verify_tls)
                    .build()?;
                Some(client)
            } else {
                None
            };

            let mut interval =
                time::interval(time::Duration::from_secs(config.poll_interval_secs));

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
                        match run_once(&config, &cf_clients, &mut cf_ip_cache, unifi_client.as_ref(), &mut unifi_ip_cache).await {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::error!("Run failed: {e}");
                            }
                        }
                    }
                    _ = sigusr1.recv() => {
                        tracing::info!("Received SIGUSR1, running update check");
                        match run_once(&config, &cf_clients, &mut cf_ip_cache, unifi_client.as_ref(), &mut unifi_ip_cache).await {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::error!("Run failed: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_once(
    config: &Config,
    cf_clients: &[CfClient],
    cf_cache: &mut HashMap<String, Ipv6Addr>,
    unifi_client: Option<&HttpClient>,
    unifi_cache: &mut HashMap<String, Ipv6Addr>,
) -> Result<()> {
    // get current public ip from local network interfaces
    let ip = find_local_ipv6(&config.if_inet6_path, config.interface.as_deref())?;

    // Update Cloudflare DNS records for each zone
    for (zone_config, cf_client) in config.cloudflare.iter().zip(cf_clients.iter()) {
        for record in &zone_config.records {
            let record_id = &record.record_id;

            // get current cloudflare record ip (from cache if available)
            let record_ip = if let Some(cached_ip) = cf_cache.get(record_id) {
                tracing::debug!(
                    "Using cached Cloudflare IP for {}: {cached_ip}",
                    record.domain_name
                );
                *cached_ip
            } else {
                let ip = find_cf_record_ip(cf_client, &zone_config.zone_id, record_id).await?;
                tracing::debug!(
                    "Retrieved Cloudflare IP from API for {}: {ip}",
                    record.domain_name
                );
                cf_cache.insert(record_id.clone(), ip);
                ip
            };

            // if ip has changed, update cloudflare record
            if ip != record_ip {
                update_cf_record(zone_config, record, cf_client, ip, cf_cache).await?;
                tracing::info!("Updated Cloudflare IP for {} to {ip}", record.domain_name);
            } else {
                tracing::info!("Cloudflare IP {ip} for {} has not changed", record.domain_name);
            }
        }
    }

    // Update UniFi address lists if configured
    if let (Some(unifi_config), Some(http_client)) = (&config.unifi, unifi_client) {
        let mut any_updated = false;
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
                        any_updated = true;
                    }
                    Err(e) => {
                        tracing::error!("Failed to update UniFi address list {list_id}: {e}");
                    }
                }
            } else {
                tracing::info!("UniFi address list {list_id} IP {ip} has not changed");
            }
        }

        if any_updated {
            for policy_id in &unifi_config.firewall_policy_ids {
                match kick_unifi_firewall_policy(http_client, unifi_config, policy_id).await {
                    Ok(()) => {
                        tracing::info!("Kicked UniFi firewall policy {policy_id}");
                    }
                    Err(e) => {
                        tracing::error!("Failed to kick UniFi firewall policy {policy_id}: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn update_cf_record(
    config: &CloudflareZoneConfig,
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
fn find_local_ipv6(if_inet6_path: &str, interface_filter: Option<&str>) -> Result<Ipv6Addr> {
    let content = fs::read_to_string(if_inet6_path)
        .with_context(|| format!("Failed to read {if_inet6_path}"))?;
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

/// RTNLGRP_IPV6_IFADDR multicast group — kernel notifies on any IPv6 address add/remove.
const RTNLGRP_IPV6_IFADDR: u32 = 9;

async fn run_ipv6_mode(output_path: PathBuf, signal_command: String) -> Result<()> {
    tracing::info!("Starting ipv6 mode, writing to {}", output_path.display());

    // Write initial state so the ddns process has a file to read on its first tick
    write_if_inet6(&output_path)?;

    let mut socket = TokioSocket::new(NETLINK_ROUTE)?;
    socket.socket_mut().bind_auto()?;
    socket.socket_mut().add_membership(RTNLGRP_IPV6_IFADDR)?;

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;

    // Buffer large enough for typical netlink messages
    let mut buf = vec![0u8; 4096];

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
            result = socket.recv(&mut buf) => {
                result.context("Netlink socket error")?;
                tracing::info!("IPv6 address change detected");
                match write_if_inet6(&output_path) {
                    Ok(()) => signal_ddns(&signal_command).await?,
                    Err(e) => tracing::error!("Failed to write if_inet6 file: {e}"),
                }
            }
        }
    }

    Ok(())
}

fn write_if_inet6(output_path: &Path) -> Result<()> {
    let content = fs::read_to_string("/proc/net/if_inet6")
        .context("Failed to read /proc/net/if_inet6")?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).context("Failed to create output directory")?;
    }
    fs::write(output_path, content)
        .with_context(|| format!("Failed to write to {}", output_path.display()))?;
    tracing::debug!("Wrote if_inet6 content to {}", output_path.display());
    Ok(())
}

async fn signal_ddns(signal_command: &str) -> Result<()> {
    tracing::info!("Running signal command: {signal_command}");
    let status = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(signal_command)
        .status()
        .await
        .context("Failed to run signal command")?;
    if !status.success() {
        tracing::warn!("Signal command exited with non-zero status: {status}");
    }
    Ok(())
}

async fn kick_unifi_firewall_policy(
    http_client: &HttpClient,
    config: &UnifiConfig,
    policy_id: &str,
) -> Result<()> {
    let url = format!(
        "{}/proxy/network/integration/v1/sites/{}/firewall/policies/{}",
        config.base_url, config.site_id, policy_id
    );

    // GET the current policy as raw JSON to avoid modelling the full schema
    let mut policy: serde_json::Value = http_client
        .get(&url)
        .header("X-API-KEY", &config.api_key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // Update the description with a timestamp
    let now = Local::now();
    policy["description"] = serde_json::json!(
        format!("Trigger re-eval - {}.", now.format("%d-%b-%Y, %H:%M"))
    );

    // Strip read-only fields the PUT endpoint does not accept
    if let Some(obj) = policy.as_object_mut() {
        obj.remove("id");
        obj.remove("index");
        obj.remove("metadata");
    }

    // PUT the policy back with the updated description
    http_client
        .put(&url)
        .header("X-API-KEY", &config.api_key)
        .header("Accept", "application/json")
        .json(&policy)
        .send()
        .await?
        .error_for_status()?;

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
