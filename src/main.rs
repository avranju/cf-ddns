mod ddns;
mod ipv6;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use ddns::run_ddns_mode;
use ipv6::run_ipv6_mode;

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

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");

    let args = Args::parse();

    match args.command {
        Command::Ddns { config } => run_ddns_mode(config).await?,
        Command::Ipv6 { output_path, signal_command } => run_ipv6_mode(output_path, signal_command).await?,
    }

    Ok(())
}
