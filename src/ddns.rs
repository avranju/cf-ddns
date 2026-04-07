use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv6Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Local;
use cloudflare::{
    endpoints::dns::dns,
    framework::{Environment, auth::Credentials, client::async_api::Client as CfClient},
};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use tokio::{signal, time};

use crate::ipv6::find_local_ipv6;

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

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
pub struct RecordConfig {
    pub record_id: String,
    pub domain_name: String,
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

// ---------------------------------------------------------------------------
// UniFi API types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Cloudflare client factory
// ---------------------------------------------------------------------------

pub async fn run_ddns_mode(config_path: PathBuf) -> Result<()> {
    let file = File::open(&config_path).context("Failed to open config file")?;
    let reader = BufReader::new(file);
    let config: Config =
        serde_json::from_reader(reader).context("Failed to parse config file")?;

    let cf_clients = build_cf_clients(&config)?;

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
    let mut cf_ip_cache = HashMap::new();

    // Cache for UniFi address list IP to avoid redundant API calls
    // Map list_id -> Ipv6Addr
    let mut unifi_ip_cache = HashMap::new();

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
                    Err(e) => tracing::error!("Run failed: {e}"),
                }
            }
            _ = sigusr1.recv() => {
                tracing::info!("Received SIGUSR1, running update check");
                match run_once(&config, &cf_clients, &mut cf_ip_cache, unifi_client.as_ref(), &mut unifi_ip_cache).await {
                    Ok(_) => {}
                    Err(e) => tracing::error!("Run failed: {e}"),
                }
            }
        }
    }

    Ok(())
}

fn build_cf_clients(config: &Config) -> Result<Vec<CfClient>> {
    config
        .cloudflare
        .iter()
        .map(|zone| {
            let credentials = Credentials::UserAuthToken {
                token: zone.api_key.clone(),
            };
            CfClient::new(credentials, Default::default(), Environment::Production)
                .map_err(anyhow::Error::from)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Main update logic
// ---------------------------------------------------------------------------

pub async fn run_once(
    config: &Config,
    cf_clients: &[CfClient],
    cf_cache: &mut HashMap<String, Ipv6Addr>,
    unifi_client: Option<&HttpClient>,
    unifi_cache: &mut HashMap<String, Ipv6Addr>,
) -> Result<()> {
    // Get current public IPv6 from local network interfaces
    let ip = find_local_ipv6(&config.if_inet6_path, config.interface.as_deref())?;

    // Update Cloudflare DNS records for each zone
    for (zone_config, cf_client) in config.cloudflare.iter().zip(cf_clients.iter()) {
        for record in &zone_config.records {
            let record_id = &record.record_id;

            // Get current Cloudflare record IP (from cache if available)
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

// ---------------------------------------------------------------------------
// Cloudflare helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// UniFi helpers
// ---------------------------------------------------------------------------

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
    // Get the current list to preserve its name
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
    policy["description"] =
        serde_json::json!(format!("Trigger re-eval - {}.", now.format("%d-%b-%Y, %H:%M")));

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
