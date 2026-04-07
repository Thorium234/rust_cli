use serde::Serialize;
use std::time::Duration;
use url::Url;

use crate::file::PathProbe;
use crate::rate_limit::RateLimitReport;
use crate::scanner::{PortResult, WebReport};

// Re-export severity for use in report formatting
#[allow(unused_imports)]
use crate::security_checks;

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
    pub duration_ports: Duration,
    pub duration_web: Duration,
    pub duration_paths: Duration,
    pub duration_rate: Duration,
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
        duration_ports: Duration,
        duration_web: Duration,
        duration_paths: Duration,
        duration_rate: Duration,
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
            duration_ports,
            duration_web,
            duration_paths,
            duration_rate,
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
    println!();
    println!("== Timing Summary ==");
    println!("  Ports:  {:?}", report.duration_ports);
    println!("  Web:    {:?}", report.duration_web);
    println!("  Paths:  {:?}", report.duration_paths);
    println!("  Rate:   {:?}", report.duration_rate);
    let total = report.duration_ports + report.duration_web + report.duration_paths + report.duration_rate;
    println!("  Total:  {:?}", total);
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

    // HTTP version
    if let Some(ref ver) = web_report.protocol_support.http_version {
        println!("HTTP Version: {ver}");
    }
    println!(
        "HTTP/2: {}, HTTP/3: {}",
        yes_no(web_report.protocol_support.http2_supported),
        yes_no(web_report.protocol_support.http3_supported)
    );

    println!("\nSecurity headers (validated):");
    for hf in &web_report.security_header_findings {
        let status = match hf.status {
            crate::security_checks::HeaderStatus::Optimal => "optimal",
            crate::security_checks::HeaderStatus::PresentButWeak => "weak",
            crate::security_checks::HeaderStatus::Missing => "missing",
            crate::security_checks::HeaderStatus::Misconfigured => "misconfigured",
        };
        let value = hf.value.as_deref().unwrap_or("-");
        println!("  {:<38} {:<14} {}", hf.name, status, value);
    }

    // CSP findings summary
    if !web_report.csp_findings.is_empty() {
        println!("\nCSP analysis ({} issues):", web_report.csp_findings.len());
        for f in &web_report.csp_findings {
            println!("  [{:>8}] {}", f.severity, f.title);
        }
    }

    // TLS info (legacy)
    println!("\nTLS:");
    if web_report.tls.enabled {
        println!("  Enabled: yes");
        if let Some(ref subject) = web_report.tls.subject {
            println!("  Subject: {subject}");
        }
        if let Some(ref issuer) = web_report.tls.issuer {
            println!("  Issuer: {issuer}");
        }
        if let Some(ref expiry) = web_report.tls.expiry {
            println!("  Expiry: {expiry}");
        }
        if let Some(days) = web_report.tls.days_until_expiry {
            println!("  Days until expiry: {days}");
        }
        if !web_report.tls.san.is_empty() {
            println!("  SANs: {}", web_report.tls.san.join(", "));
        }
    } else {
        println!("  Enabled: no (HTTP only)");
    }

    // TLS config
    if let Some(ref ver) = web_report.tls_config.protocol_version {
        println!("\nTLS Config:");
        println!("  Protocol: {ver}");
    }
    if let Some(ref cipher) = web_report.tls_config.cipher_suite {
        println!("  Cipher: {cipher}");
    }
    if let Some(ks) = web_report.tls_config.key_size {
        println!("  Key size: {ks} bits");
    }
    if let Some(ref sig) = web_report.tls_config.signature_algorithm {
        println!("  Signature: {sig}");
    }
    if web_report.tls_config.is_self_signed {
        println!("  WARNING: Self-signed certificate");
    }
    if web_report.tls_config.hostname_mismatch {
        println!("  WARNING: Hostname mismatch");
    }

    // HSTS preload
    println!("\nHSTS Preload Eligibility:");
    println!("  HSTS present: {}", yes_no(web_report.hsts_preload.hsts_present));
    println!("  Sufficient max-age: {}", yes_no(web_report.hsts_preload.sufficient_max_age));
    println!("  includeSubDomains: {}", yes_no(web_report.hsts_preload.has_include_subdomains));
    println!("  preload directive: {}", yes_no(web_report.hsts_preload.has_preload));
    println!("  Preload eligible: {}", yes_no(web_report.hsts_preload.preload_eligible));

    // Redirect chain
    if !web_report.redirects.is_empty() {
        println!("\nRedirect chain:");
        for hop in &web_report.redirects {
            println!("  [{}] {} -> {} ({})", hop.index, hop.from_url, hop.to_url, hop.status);
        }
    }

    // Cookie security (enhanced)
    if !web_report.enhanced_cookies.is_empty() {
        println!("\nCookie security (enhanced):");
        for cookie in &web_report.enhanced_cookies {
            let flags = [
                if cookie.secure { "Secure" } else { "!Secure" },
                if cookie.httponly { "HttpOnly" } else { "!HttpOnly" },
                format!("SameSite={}", cookie.samesite.as_deref().unwrap_or("unset")).as_str(),
            ].join(", ");
            let prefix = if cookie.has_host_prefix {
                "__Host-"
            } else if cookie.has_secure_prefix {
                "__Secure-"
            } else {
                ""
            };
            println!("  {}{} [{}] ({} findings)", prefix, cookie.name, flags, cookie.findings.len());
            for f in &cookie.findings {
                println!("    [{:>8}] {}", f.severity, f.title);
            }
        }
    } else if !web_report.cookies.is_empty() {
        println!("\nCookie security:");
        for cookie in &web_report.cookies {
            let flags = [
                if cookie.secure { "Secure" } else { "!Secure" },
                if cookie.httponly { "HttpOnly" } else { "!HttpOnly" },
                cookie.samesite.as_deref().unwrap_or("!SameSite"),
            ].join(", ");
            println!("  {} [{flags}]", cookie.name);
        }
    }

    // HTTP Method probes
    if !web_report.method_probes.is_empty() {
        println!("\nHTTP Method Probes:");
        for mp in &web_report.method_probes {
            let status_str = mp.status.map(|s| s.to_string()).unwrap_or_else(|| "error".to_string());
            let risk_str = mp.risk.as_ref().map(|r| format!(" [{r}]")).unwrap_or_default();
            println!("  {:<8} {}{}", mp.method, status_str, risk_str);
        }
    }

    // Cache control
    println!("\nCache Control:");
    if let Some(ref cc) = web_report.cache_control.cache_control {
        println!("  Cache-Control: {cc}");
    }
    if let Some(ref p) = web_report.cache_control.pragma {
        println!("  Pragma: {p}");
    }

    // Mixed content
    if !web_report.mixed_content.is_empty() {
        println!("\nMixed Content ({} issues):", web_report.mixed_content.len());
        for mc in &web_report.mixed_content {
            println!("  [{:>8}] {} <- {}", mc.severity, mc.element_type, mc.url);
        }
    }

    // Info disclosure
    if !web_report.info_disclosure.disclosing_headers.is_empty() {
        println!("\nInformation Disclosure:");
        for disc in &web_report.info_disclosure.disclosing_headers {
            println!("  [{:>8}] {}: {}", disc.severity, disc.header, disc.value);
        }
    }

    // CORS (enhanced)
    println!("\nCORS:");
    if web_report.cors_preflight.allow_origin.is_some() {
        let origin = web_report.cors_preflight.allow_origin.as_deref().unwrap_or("not set");
        let wildcard = if web_report.cors_preflight.wildcard_with_credentials { " (wildcard+creds!)" } else { "" };
        println!("  Allow-Origin: {origin}{wildcard}");
        if let Some(ref m) = web_report.cors_preflight.allow_methods {
            println!("  Allow-Methods: {m}");
        }
        if let Some(ref c) = web_report.cors_preflight.allow_credentials {
            println!("  Allow-Credentials: {c}");
        }
        println!("  Vary: Origin: {}", yes_no(web_report.cors_preflight.vary_origin));
        println!("  Origin reflection: {}", yes_no(web_report.cors_preflight.origin_reflection));
        println!("  Excessive Max-Age: {}", yes_no(web_report.cors_preflight.excessive_max_age));
        if !web_report.cors_preflight.findings.is_empty() {
            for f in &web_report.cors_preflight.findings {
                println!("    [{:>8}] {}", f.severity, f.title);
            }
        }
    } else {
        println!("  No CORS headers detected");
    }

    // Clickjacking
    println!("\nClickjacking Protection:");
    println!("  Protected: {}", yes_no(web_report.clickjacking.protected));
    if let Some(ref xfo) = web_report.clickjacking.x_frame_options {
        println!("  X-Frame-Options: {xfo}");
    }
    println!("  CSP frame-ancestors: {}", yes_no(web_report.clickjacking.csp_frame_ancestors));

    // Technology fingerprint
    if !web_report.tech.detected_technologies.is_empty() {
        println!("\nDetected technologies: {}", web_report.tech.detected_technologies.join(", "));
    }

    // Robots.txt review
    if let Some(ref rr) = web_report.robots_review {
        if !rr.sensitive_paths.is_empty() {
            println!("\nrobots.txt sensitive paths ({}):", rr.sensitive_paths.len());
            for p in &rr.sensitive_paths {
                println!("  {p}");
            }
        }
    }

    // security.txt
    if let Some(ref st) = web_report.security_txt {
        println!("\nsecurity.txt:");
        println!("  Contact: {}", yes_no(st.has_contact));
        println!("  Expires: {} (valid: {})", yes_no(st.has_expires), yes_no(st.expires_valid));
        if !st.findings.is_empty() {
            for f in &st.findings {
                println!("    [{:>8}] {}", f.severity, f.title);
            }
        }
    }

    // SRI
    if let Some(ref sri) = web_report.sri {
        if !sri.missing_integrity.is_empty() {
            println!("\nSRI - Missing integrity for {} cross-origin resources:", sri.missing_integrity.len());
            for url in &sri.missing_integrity {
                println!("  {url}");
            }
        } else {
            println!("\nSRI: All {} cross-origin resources have integrity hashes", sri.resources_checked);
        }
    }

    // All findings summary
    if !web_report.all_findings.is_empty() {
        println!("\n== All Findings Summary ({} total) ==", web_report.all_findings.len());
        let critical: Vec<_> = web_report.all_findings.iter().filter(|f| f.severity == crate::security_checks::Severity::Critical).collect();
        let high: Vec<_> = web_report.all_findings.iter().filter(|f| f.severity == crate::security_checks::Severity::High).collect();
        let medium: Vec<_> = web_report.all_findings.iter().filter(|f| f.severity == crate::security_checks::Severity::Medium).collect();
        let low: Vec<_> = web_report.all_findings.iter().filter(|f| f.severity == crate::security_checks::Severity::Low).collect();
        let info: Vec<_> = web_report.all_findings.iter().filter(|f| f.severity == crate::security_checks::Severity::Info).collect();

        if !critical.is_empty() { println!("  CRITICAL: {}", critical.len()); }
        if !high.is_empty() { println!("  HIGH:     {}", high.len()); }
        if !medium.is_empty() { println!("  MEDIUM:   {}", medium.len()); }
        if !low.is_empty() { println!("  LOW:      {}", low.len()); }
        if !info.is_empty() { println!("  INFO:     {}", info.len()); }
    }

    println!("\nPublic path checks:");
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
