use std::net::{IpAddr, Ipv6Addr};

use anyhow::Result;
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
    /// Cloudflare API Token
    #[arg(short, long, env = "CFDNS_CLOUDFLARE_API_KEY")]
    api_key: String,

    /// Zone ID
    #[arg(short, long, env = "CFDNS_CLOUDFLARE_ZONE_ID")]
    zone_id: String,

    /// Record ID
    #[arg(short, long, env = "CFDNS_CLOUDFLARE_RECORD_ID")]
    record_id: String,

    /// Domain name
    #[arg(short, long, env = "CFDNS_DOMAIN_NAME")]
    domain_name: String,

    /// Proxied
    #[arg(short, long, env = "CFDNS_PROXIED", default_value_t = true)]
    proxied: bool,

    /// Interval at which to poll for IP changes (in seconds)
    #[arg(
        short = 'i',
        long,
        env = "CFDNS_POLL_INTERVAL_SECS",
        default_value_t = 300
    )]
    poll_interval_secs: u64,
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

    let credentials = Credentials::UserAuthToken {
        token: args.api_key.clone(),
    };
    let client = CfClient::new(credentials, Default::default(), Environment::Production)?;

    let mut interval = time::interval(time::Duration::from_secs(args.poll_interval_secs));

    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())?;

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
                match run_once(&args, &client).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("Run failed: {e}");
                    }
                }
            }
            _ = sigusr1.recv() => {
                tracing::info!("Received SIGUSR1, running update check");
                match run_once(&args, &client).await {
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

async fn run_once(args: &Args, client: &CfClient) -> Result<()> {
    // get current public ip
    let ip = find_public_ip().await?;
    let ip = ip.parse::<Ipv6Addr>().map_err(|e| {
        tracing::warn!("Failed to parse public IP: {e}");
        e
    })?;

    // get current cloudflare record ip
    let record_ip = find_cf_record_ip(client, &args.zone_id, &args.record_id).await?;

    // if ip has changed, update cloudflare record
    if ip != record_ip {
        update_cf_record(args, client, ip).await?;
        tracing::info!("Updated IP {ip}");
    } else {
        tracing::info!("IP {ip} has not changed");
    }

    Ok(())
}

async fn update_cf_record(args: &Args, client: &CfClient, ip: Ipv6Addr) -> Result<()> {
    let endpoint = dns::UpdateDnsRecord {
        zone_identifier: &args.zone_id,
        identifier: &args.record_id,
        params: dns::UpdateDnsRecordParams {
            content: dns::DnsContent::AAAA { content: ip },
            proxied: Some(args.proxied),
            ttl: None,
            name: &args.domain_name,
        },
    };

    let _ = client.request(&endpoint).await?;

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
