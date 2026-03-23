mod file;
mod rate_limit;
mod report;
mod scanner;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use std::time::Duration;
use url::Url;

use crate::file::probe_common_paths;
use crate::rate_limit::probe_rate_limiting;
use crate::report::print_report;
use crate::scanner::{scan_ports, web_probe};

#[derive(Debug, Parser)]
#[command(
    name = "web-security-auditor",
    version,
    about = "Authorized, defensive web application security auditing CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Audit {
        #[arg(help = "Base URL to audit, e.g. https://example.com")]
        url: String,
        #[arg(long, help = "Optional host/IP for TCP port checks")]
        host: Option<String>,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "80,443,8080,8443",
            help = "Comma-separated ports to probe"
        )]
        ports: Vec<u16>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Additional public paths to check, e.g. /admin,/login,/api/health"
        )]
        paths: Vec<String>,
        #[arg(
            long,
            default_value_t = 6,
            help = "Number of requests for rate-limit probing"
        )]
        rate_requests: usize,
        #[arg(long, default_value_t = 10, help = "HTTP timeout in seconds")]
        timeout_secs: u64,
    },
    Ports {
        #[arg(help = "Host or IP address for TCP connect checks")]
        host: String,
        #[arg(long, value_delimiter = ',', default_value = "80,443,8080,8443")]
        ports: Vec<u16>,
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
    },
    Web {
        #[arg(help = "Base URL to inspect")]
        url: String,
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
    },
    Rate {
        #[arg(help = "Base URL to test for visible rate limiting")]
        url: String,
        #[arg(long, default_value_t = 6)]
        requests: usize,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            url,
            host,
            ports,
            paths,
            rate_requests,
            timeout_secs,
        } => {
            let base_url = parse_url(&url)?;
            let client = build_client(timeout_secs)?;
            let target_host = host.unwrap_or_else(|| {
                base_url
                    .host_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| "localhost".to_string())
            });

            let port_report = scan_ports(&target_host, &ports, Duration::from_millis(800));
            let web_report = web_probe(&client, &base_url)?;
            let path_report = probe_common_paths(&client, &base_url, &paths)?;
            let rate_report = probe_rate_limiting(&client, &base_url, rate_requests)?;

            print_report(
                &base_url,
                &target_host,
                port_report,
                web_report,
                path_report,
                rate_report,
            );
        }
        Commands::Ports {
            host,
            ports,
            timeout_ms,
        } => {
            let report = scan_ports(&host, &ports, Duration::from_millis(timeout_ms));
            report::print_port_report(&host, &report);
        }
        Commands::Web {
            url,
            paths,
            timeout_secs,
        } => {
            let base_url = parse_url(&url)?;
            let client = build_client(timeout_secs)?;
            let web_report = web_probe(&client, &base_url)?;
            let path_report = probe_common_paths(&client, &base_url, &paths)?;
            report::print_web_report(&base_url, web_report, path_report);
        }
        Commands::Rate {
            url,
            requests,
            timeout_secs,
        } => {
            let base_url = parse_url(&url)?;
            let client = build_client(timeout_secs)?;
            let rate_report = probe_rate_limiting(&client, &base_url, requests)?;
            report::print_rate_report(&base_url, rate_report);
        }
    }

    Ok(())
}

fn parse_url(input: &str) -> Result<Url> {
    let url = Url::parse(input).with_context(|| format!("invalid URL: {input}"))?;
    if url.host_str().is_none() {
        anyhow::bail!("URL must include a host");
    }
    Ok(url)
}

fn build_client(timeout_secs: u64) -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("web-security-auditor/0.1")
        .build()
        .context("failed to build HTTP client")
}
