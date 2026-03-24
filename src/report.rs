use serde::Serialize;
use url::Url;

use crate::file::PathProbe;
use crate::rate_limit::RateLimitReport;
use crate::scanner::{PortResult, WebReport};

pub const SCHEMA_VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub schema_version: &'static str,
    pub target_url: String,
    pub host: String,
    pub worker_count: usize,
    pub ports: Vec<PortResult>,
    pub web: WebReport,
    pub paths: Vec<PathProbe>,
    pub rate_limit: RateLimitReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebOutput {
    pub schema_version: &'static str,
    pub target_url: String,
    pub worker_count: usize,
    pub web: WebReport,
    pub paths: Vec<PathProbe>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortsOutput {
    pub schema_version: &'static str,
    pub host: String,
    pub worker_count: usize,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RateOutput {
    pub schema_version: &'static str,
    pub target_url: String,
    pub rate_limit: RateLimitReport,
}

impl AuditReport {
    pub fn new(
        target_url: String,
        host: String,
        worker_count: usize,
        ports: Vec<PortResult>,
        web: WebReport,
        paths: Vec<PathProbe>,
        rate_limit: RateLimitReport,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            target_url,
            host,
            worker_count,
            ports,
            web,
            paths,
            rate_limit,
        }
    }
}

impl WebOutput {
    pub fn new(
        target_url: String,
        worker_count: usize,
        web: WebReport,
        paths: Vec<PathProbe>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            target_url,
            worker_count,
            web,
            paths,
        }
    }
}

impl PortsOutput {
    pub fn new(host: String, worker_count: usize, ports: Vec<PortResult>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            host,
            worker_count,
            ports,
        }
    }
}

impl RateOutput {
    pub fn new(target_url: String, rate_limit: RateLimitReport) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            target_url,
            rate_limit,
        }
    }
}

pub fn emit_audit_report(report: &AuditReport, output: OutputFormat) {
    match output {
        OutputFormat::Text => print_report(report),
        OutputFormat::Json => print_json(report),
    }
}

pub fn emit_ports_report(report: &PortsOutput, output: OutputFormat) {
    match output {
        OutputFormat::Text => print_port_report(&report.host, &report.ports),
        OutputFormat::Json => print_json(report),
    }
}

pub fn emit_web_report(report: &WebOutput, output: OutputFormat) {
    match output {
        OutputFormat::Text => print_web_report_from_data(report),
        OutputFormat::Json => print_json(report),
    }
}

pub fn emit_rate_report(report: &RateOutput, output: OutputFormat) {
    match output {
        OutputFormat::Text => print_rate_report_from_data(report),
        OutputFormat::Json => print_json(report),
    }
}

fn print_report(report: &AuditReport) {
    println!("Target URL: {}", report.target_url);
    println!("Host for TCP checks: {}", report.host);
    println!("Worker count: {}", report.worker_count);
    println!();
    print_port_report(&report.host, &report.ports);
    println!();
    print_web_report(
        &parse_url(&report.target_url),
        report.web.clone(),
        report.paths.clone(),
    );
    println!();
    print_rate_report(&parse_url(&report.target_url), report.rate_limit.clone());
}

pub fn print_port_report(host: &str, port_report: &[PortResult]) {
    println!("== Port Scan ({host}) ==");
    for entry in port_report {
        println!("{:>5}/tcp  {}", entry.port, entry.state);
    }
}

pub fn print_web_report(base_url: &Url, web_report: WebReport, path_report: Vec<PathProbe>) {
    println!("== Web Probe ({base_url}) ==");
    println!("Final URL: {}", web_report.final_url);
    println!("HTTP Status: {}", web_report.status);
    println!(
        "Server: {}",
        web_report.server.as_deref().unwrap_or("not disclosed")
    );
    println!(
        "X-Powered-By: {}",
        web_report.powered_by.as_deref().unwrap_or("not disclosed")
    );
    println!(
        "Content-Type: {}",
        web_report.content_type.as_deref().unwrap_or("unknown")
    );
    println!(
        "Public metadata: robots.txt={}, sitemap.xml={}",
        yes_no(web_report.robots_txt_present),
        yes_no(web_report.sitemap_present)
    );
    println!("Security headers:");
    for header in web_report.security_headers {
        let status = if header.present { "present" } else { "missing" };
        let value = header.value.unwrap_or_else(|| "-".to_string());
        println!("  {:<28} {:<8} {}", header.name, status, value);
    }
    println!("Public path checks:");
    for item in path_report {
        let status = item
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "error".to_string());
        let marker = if item.interesting {
            "interesting"
        } else {
            "normal"
        };
        println!("  {:<28} {:<5} {}", item.path, status, marker);
    }
}

pub fn print_rate_report(base_url: &Url, rate_report: RateLimitReport) {
    println!("== Rate Limiting ({base_url}) ==");
    println!(
        "Visible rate limiting detected: {}",
        yes_no(rate_report.limit_detected)
    );
    for item in rate_report.observations {
        let status = item
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "error".to_string());
        println!(
            "  Attempt {:>2}: status={} retry-after={} remaining={}",
            item.attempt,
            status,
            item.retry_after.as_deref().unwrap_or("-"),
            item.remaining.as_deref().unwrap_or("-")
        );
    }
}

fn print_web_report_from_data(report: &WebOutput) {
    println!("Worker count: {}", report.worker_count);
    print_web_report(
        &parse_url(&report.target_url),
        report.web.clone(),
        report.paths.clone(),
    );
}

fn print_rate_report_from_data(report: &RateOutput) {
    print_rate_report(&parse_url(&report.target_url), report.rate_limit.clone());
}

fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("error: failed to serialize JSON output: {error}");
            std::process::exit(1);
        }
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn parse_url(input: &str) -> Url {
    Url::parse(input).expect("stored report URL should always be valid")
}
