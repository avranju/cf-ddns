use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv6Addr};
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
    pub api_key: String,
    pub zone_id: String,
    #[serde(default = "default_proxied")]
    pub proxied: bool,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    pub records: Vec<RecordConfig>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAgent {
    pub product: String,
    pub version: String,
    pub comment: String,
    pub raw_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    pub country: String,
    pub country_iso: String,
    pub country_eu: bool,
    pub region_name: String,
    pub region_code: String,
    pub zip_code: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub time_zone: String,
    pub asn: String,
    pub asn_org: String,
    pub user_agent: Option<UserAgent>,
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
        token: config.api_key.clone(),
    };
    let client = CfClient::new(credentials, Default::default(), Environment::Production)?;

    let mut interval = time::interval(time::Duration::from_secs(config.poll_interval_secs));

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;

    // Cache for Cloudflare record IP to avoid redundant API calls
    // Map record_id -> Ipv6Addr
    let mut cf_ip_cache: HashMap<String, Ipv6Addr> = HashMap::new();

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
                match run_once(&config, &client, &mut cf_ip_cache).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("Run failed: {e}");
                    }
                }
            }
            _ = sigusr1.recv() => {
                tracing::info!("Received SIGUSR1, running update check");
                match run_once(&config, &client, &mut cf_ip_cache).await {
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
    client: &CfClient,
    cache: &mut HashMap<String, Ipv6Addr>,
) -> Result<()> {
    // get current public ip
    let ip = find_public_ip().await?;
    let ip = ip.parse::<Ipv6Addr>().map_err(|e| {
        tracing::warn!("Failed to parse public IP: {e}");
        e
    })?;

    for record in &config.records {
        let record_id = &record.record_id;

        // get current cloudflare record ip (from cache if available)
        let record_ip = if let Some(cached_ip) = cache.get(record_id) {
            tracing::debug!(
                "Using cached Cloudflare IP for {}: {cached_ip}",
                record.domain_name
            );
            *cached_ip
        } else {
            let ip = find_cf_record_ip(client, &config.zone_id, record_id).await?;
            tracing::debug!(
                "Retrieved Cloudflare IP from API for {}: {ip}",
                record.domain_name
            );
            cache.insert(record_id.clone(), ip);
            ip
        };

        // if ip has changed, update cloudflare record
        if ip != record_ip {
            update_cf_record(config, record, client, ip, cache).await?;
            tracing::info!("Updated IP for {} to {ip}", record.domain_name);
        } else {
            tracing::info!("IP {ip} for {} has not changed", record.domain_name);
        }
    }

    Ok(())
}

async fn update_cf_record(
    config: &Config,
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

async fn find_public_ip() -> Result<String> {
    let client = HttpClient::builder()
        .local_address(IpAddr::from(Ipv6Addr::UNSPECIFIED))
        .build()?;

    let resp = client.get("https://ifconfig.co/json").send().await?;

    let ip = resp.json::<IpInfo>().await?;

    Ok(ip.ip)
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
