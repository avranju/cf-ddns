use std::fs;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use netlink_sys::{AsyncSocket, AsyncSocketExt, TokioSocket, protocols::NETLINK_ROUTE};
use tokio::signal;

/// RTNLGRP_IPV6_IFADDR multicast group — kernel notifies on any IPv6 address add/remove.
const RTNLGRP_IPV6_IFADDR: u32 = 9;

/// Parses IPv6 addresses from /proc/net/if_inet6 content.
///
/// The format is: address device_index prefix_len scope flags interface_name
///
/// Only returns addresses where:
/// - scope is 0x00 (global)
/// - IFA_F_TEMPORARY flag (0x01) is NOT set
pub fn parse_ipv6_from_proc_content(
    content: &str,
    interface_filter: Option<&str>,
) -> Result<Ipv6Addr> {
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
/// Reads from the given if_inet6 path and parses the content to find suitable addresses.
pub fn find_local_ipv6(if_inet6_path: &str, interface_filter: Option<&str>) -> Result<Ipv6Addr> {
    let content = fs::read_to_string(if_inet6_path)
        .with_context(|| format!("Failed to read {if_inet6_path}"))?;
    parse_ipv6_from_proc_content(&content, interface_filter)
}

/// Monitors IPv6 address changes via netlink and writes the if_inet6 file on each change.
pub async fn run_ipv6_mode(output_path: PathBuf, signal_command: String) -> Result<()> {
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No suitable global non-temporary IPv6 address found"));
    }

    #[test]
    fn test_parse_ipv6_from_proc_content_empty_content() {
        let content = "";

        let result = parse_ipv6_from_proc_content(content, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No suitable global non-temporary IPv6 address found"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No suitable global non-temporary IPv6 address found on interface eth1"));
    }
}
