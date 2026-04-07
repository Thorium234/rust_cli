mod file;
mod rate_limit;
mod report;
mod scanner;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::blocking::Client;
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

use crate::file::probe_common_paths;
use crate::rate_limit::probe_rate_limiting;
use crate::report::{
    emit_audit_report, emit_ports_report, emit_rate_report, emit_web_report, AuditReport,
    OutputFormat, PortsOutput, RateOutput, WebOutput,
};
use crate::scanner::{scan_ports, web_probe};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliOutputFormat {
    Text,
    Json,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => OutputFormat::Text,
            CliOutputFormat::Json => OutputFormat::Json,
        }
    }
}

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
        #[arg(
            long,
            default_value_t = 8,
            help = "Max concurrent workers for port and path probes"
        )]
        workers: usize,
        #[arg(long, value_enum, default_value_t = CliOutputFormat::Text)]
        output: CliOutputFormat,
    },
    Ports {
        #[arg(help = "Host or IP address for TCP connect checks")]
        host: String,
        #[arg(long, value_delimiter = ',', default_value = "80,443,8080,8443")]
        ports: Vec<u16>,
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
        #[arg(
            long,
            default_value_t = 8,
            help = "Max concurrent workers for TCP port probes"
        )]
        workers: usize,
        #[arg(long, value_enum, default_value_t = CliOutputFormat::Text)]
        output: CliOutputFormat,
    },
    Web {
        #[arg(help = "Base URL to inspect")]
        url: String,
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        #[arg(
            long,
            default_value_t = 8,
            help = "Max concurrent workers for path probes"
        )]
        workers: usize,
        #[arg(long, value_enum, default_value_t = CliOutputFormat::Text)]
        output: CliOutputFormat,
    },
    Rate {
        #[arg(help = "Base URL to test for visible rate limiting")]
        url: String,
        #[arg(long, default_value_t = 6)]
        requests: usize,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        #[arg(long, value_enum, default_value_t = CliOutputFormat::Text)]
        output: CliOutputFormat,
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
            workers,
            output,
        } => {
            let base_url = parse_url(&url)?;
            let client = build_client(timeout_secs)?;
            let target_host = host.unwrap_or_else(|| {
                base_url
                    .host_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| "localhost".to_string())
            });

            let ports_for_thread = ports.clone();
            let paths_for_thread = paths.clone();
            let base_for_web = base_url.clone();
            let base_for_paths = base_url.clone();
            let base_for_rate = base_url.clone();
            let host_for_ports = target_host.clone();

            let port_handle = thread::spawn(move || {
                let start = Instant::now();
                let results = scan_ports(
                    &host_for_ports,
                    &ports_for_thread,
                    Duration::from_millis(800),
                    workers,
                );
                (results, start.elapsed())
            });
            let web_start = Instant::now();
            let web_client = client.clone();
            let web_handle = thread::spawn(move || web_probe(&web_client, &base_for_web));
            let path_start = Instant::now();
            let path_client = client.clone();
            let path_handle = thread::spawn(move || {
                probe_common_paths(&path_client, &base_for_paths, &paths_for_thread, workers)
            });
            let rate_start = Instant::now();
            let rate_client = client.clone();
            let rate_handle = thread::spawn(move || {
                probe_rate_limiting(&rate_client, &base_for_rate, rate_requests)
            });

            let (ports_data, duration_ports) = port_handle.join().expect("port scan thread panicked");
            let web_result = web_handle.join().expect("web probe thread panicked")?;
            let duration_web = web_start.elapsed();
            let paths = path_handle.join().expect("path probe thread panicked")?;
            let duration_paths = path_start.elapsed();
            let rate = rate_handle.join().expect("rate-limit thread panicked")?;
            let duration_rate = rate_start.elapsed();

            let report = AuditReport::new(
                base_url.to_string(),
                target_host,
                workers,
                ports_data,
                web_result,
                paths,
                rate,
                duration_ports,
                duration_web,
                duration_paths,
                duration_rate,
            );

            emit_audit_report(&report, output.into());
        }
        Commands::Ports {
            host,
            ports,
            timeout_ms,
            workers,
            output,
        } => {
            let report = PortsOutput::new(
                host.clone(),
                workers,
                scan_ports(&host, &ports, Duration::from_millis(timeout_ms), workers),
            );
            emit_ports_report(&report, output.into());
        }
        Commands::Web {
            url,
            paths,
            timeout_secs,
            workers,
            output,
        } => {
            let base_url = parse_url(&url)?;
            let client = build_client(timeout_secs)?;
            let web_client = client.clone();
            let path_client = client.clone();
            let web_base = base_url.clone();
            let path_base = base_url.clone();
            let path_values = paths.clone();

            let web_handle = thread::spawn(move || web_probe(&web_client, &web_base));
            let path_handle = thread::spawn(move || {
                probe_common_paths(&path_client, &path_base, &path_values, workers)
            });

            let report = WebOutput::new(
                base_url.to_string(),
                workers,
                web_handle.join().expect("web probe thread panicked")?,
                path_handle.join().expect("path probe thread panicked")?,
            );
            emit_web_report(&report, output.into());
        }
        Commands::Rate {
            url,
            requests,
            timeout_secs,
            output,
        } => {
            let base_url = parse_url(&url)?;
            let client = build_client(timeout_secs)?;
            let report = RateOutput::new(
                base_url.to_string(),
                probe_rate_limiting(&client, &base_url, requests)?,
            );
            emit_rate_report(&report, output.into());
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
