use url::Url;

use crate::file::PathProbe;
use crate::rate_limit::RateLimitReport;
use crate::scanner::{PortResult, WebReport};

pub fn print_report(
    base_url: &Url,
    host: &str,
    port_report: Vec<PortResult>,
    web_report: WebReport,
    path_report: Vec<PathProbe>,
    rate_report: RateLimitReport,
) {
    println!("Target URL: {base_url}");
    println!("Host for TCP checks: {host}");
    println!();
    print_port_report(host, &port_report);
    println!();
    print_web_report(base_url, web_report, path_report);
    println!();
    print_rate_report(base_url, rate_report);
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

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
