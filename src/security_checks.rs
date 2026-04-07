use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use regex::Regex;
use reqwest::blocking::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use url::Url;

// ============================================================
// Severity levels
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

// ============================================================
// Generic finding
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
    pub detail: Option<String>,
}

impl Finding {
    pub fn new(id: &str, title: &str, severity: Severity, description: &str, remediation: &str) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            severity,
            description: description.to_string(),
            remediation: remediation.to_string(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: String) -> Self {
        self.detail = Some(detail);
        self
    }
}

// ============================================================
// 1. Expanded HTTP Security Header Analysis
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct HeaderFinding {
    pub name: String,
    pub present: bool,
    pub value: Option<String>,
    pub status: HeaderStatus,
    pub finding: Option<Finding>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderStatus {
    Optimal,
    PresentButWeak,
    Missing,
    Misconfigured,
}

pub fn analyze_security_headers(headers: &reqwest::header::HeaderMap) -> Vec<HeaderFinding> {
    let mut results = Vec::new();

    // Core headers already covered elsewhere, but we validate values here
    let core_checks: Vec<(&str, Box<dyn Fn(Option<&str>) -> (HeaderStatus, Option<Finding>)>)> = vec![
        (
            "strict-transport-security",
            Box::new(|val| validate_hsts(val)),
        ),
        (
            "content-security-policy",
            Box::new(|val| validate_csp_presence(val)),
        ),
        (
            "x-frame-options",
            Box::new(|val| validate_x_frame_options(val)),
        ),
        (
            "x-content-type-options",
            Box::new(|val| validate_x_content_type_options(val)),
        ),
        (
            "referrer-policy",
            Box::new(|val| validate_referrer_policy(val)),
        ),
        (
            "permissions-policy",
            Box::new(|val| validate_permissions_policy(val)),
        ),
        (
            "cross-origin-opener-policy",
            Box::new(|val| validate_coop(val)),
        ),
        (
            "cross-origin-embedder-policy",
            Box::new(|val| validate_coep(val)),
        ),
        (
            "cross-origin-resource-policy",
            Box::new(|val| validate_corp(val)),
        ),
        (
            "x-permitted-cross-domain-policies",
            Box::new(|val| validate_x_permitted_cross_domain_policies(val)),
        ),
        (
            "x-dns-prefetch-control",
            Box::new(|val| validate_x_dns_prefetch_control(val)),
        ),
        (
            "clear-site-data",
            Box::new(|val| validate_clear_site_data(val)),
        ),
    ];

    for (name, validator) in core_checks {
        let raw_value = headers.get(name).and_then(|v| v.to_str().ok());
        let (status, finding) = validator(raw_value);
        results.push(HeaderFinding {
            name: name.to_string(),
            present: raw_value.is_some(),
            value: raw_value.map(ToOwned::to_owned),
            status,
            finding,
        });
    }

    results
}

fn validate_hsts(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let val = match val {
        Some(v) => v,
        None => {
            return (
                HeaderStatus::Missing,
                Some(Finding::new(
                    "HSTS-001",
                    "Missing Strict-Transport-Security header",
                    Severity::High,
                    "HSTS instructs browsers to enforce HTTPS. Without it, users are vulnerable to protocol downgrade attacks.",
                    "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                )),
            );
        }
    };

    let lower = val.to_lowercase();
    let max_age = extract_hsts_max_age(val);
    let has_include_subdomains = lower.contains("includesubdomains");
    let has_preload = lower.contains("preload");

    let mut issues = Vec::new();
    if max_age < 31536000 {
        issues.push("max-age < 31536000");
    }
    if !has_include_subdomains {
        issues.push("missing includeSubDomains");
    }
    if !has_preload {
        issues.push("missing preload");
    }

    if issues.is_empty() {
        (HeaderStatus::Optimal, None)
    } else {
        (
            HeaderStatus::PresentButWeak,
            Some(Finding::new(
                "HSTS-002",
                "HSTS header present but not optimal",
                Severity::Medium,
                &format!("Issues: {}", issues.join(", ")),
                "Set max-age >= 31536000, include includeSubDomains and preload directives.",
            ).with_detail(format!("Value: {val}"))),
        )
    }
}

fn extract_hsts_max_age(val: &str) -> i64 {
    val.split(';')
        .find_map(|part| {
            let trimmed = part.trim().to_lowercase();
            if trimmed.starts_with("max-age=") {
                trimmed.strip_prefix("max-age=")?.parse::<i64>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn validate_csp_presence(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    match val {
        Some(v) => {
            let findings = analyze_csp_directives(v);
            if findings.is_empty() {
                (HeaderStatus::Optimal, None)
            } else {
                let critical: Vec<_> = findings.iter().filter(|f| f.severity >= Severity::High).collect();
                let sev = if critical.is_empty() { Severity::Medium } else { Severity::High };
                (HeaderStatus::PresentButWeak, Some(Finding::new(
                    "CSP-001",
                    "Content Security Policy has weaknesses",
                    sev,
                    &format!("{} directive issues found", findings.len()),
                    "Review and strengthen CSP directives. Remove unsafe-inline, unsafe-eval, and wildcards.",
                ).with_detail(format!("Issues: {}", findings.iter().map(|f| f.title.as_str()).collect::<Vec<_>>().join("; ")))))
            }
        }
        None => (
            HeaderStatus::Missing,
            Some(Finding::new(
                "CSP-002",
                "Missing Content-Security-Policy header",
                Severity::High,
                "CSP mitigates XSS and data injection attacks. Without it, the application has no browser-level content restrictions.",
                "Add a restrictive CSP header with allowlisted sources for scripts, styles, and other resources.",
            )),
        ),
    }
}

pub fn analyze_csp_directives(csp_value: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let directives: HashMap<String, Vec<&str>> = csp_value
        .split(';')
        .filter_map(|d| {
            let parts: Vec<&str> = d.trim().splitn(2, char::is_whitespace).collect();
            if parts.is_empty() || parts[0].is_empty() {
                None
            } else {
                let values = if parts.len() > 1 {
                    parts[1].split_whitespace().collect()
                } else {
                    vec![]
                };
                Some((parts[0].to_lowercase(), values))
            }
        })
        .collect();

    // Check for unsafe-inline
    for (directive, values) in &directives {
        if values.iter().any(|v| *v == "'unsafe-inline'") {
            findings.push(Finding::new(
                "CSP-DIR-001",
                &format!("CSP directive '{directive}' uses 'unsafe-inline'"),
                Severity::High,
                "'unsafe-inline' allows arbitrary inline scripts/styles, defeating XSS protection.",
                "Remove 'unsafe-inline' and use nonces or hashes for inline content.",
            ).with_detail(format!("Directive: {directive}")));
        }
    }

    // Check for unsafe-eval
    for (directive, values) in &directives {
        if values.iter().any(|v| *v == "'unsafe-eval'") {
            findings.push(Finding::new(
                "CSP-DIR-002",
                &format!("CSP directive '{directive}' uses 'unsafe-eval'"),
                Severity::High,
                "'unsafe-eval' allows dynamic code execution via eval(), Function(), etc.",
                "Remove 'unsafe-eval' and refactor code to avoid dynamic code evaluation.",
            ).with_detail(format!("Directive: {directive}")));
        }
    }

    // Check for wildcard sources
    for (directive, values) in &directives {
        if values.iter().any(|v| *v == "*") {
            findings.push(Finding::new(
                "CSP-DIR-003",
                &format!("CSP directive '{directive}' uses wildcard '*'"),
                Severity::Medium,
                "Wildcard sources allow loading resources from any origin, weakening the allowlist model.",
                "Replace '*' with specific trusted origins.",
            ).with_detail(format!("Directive: {directive}")));
        }
    }

    // Check missing critical directives
    if !directives.contains_key("default-src") {
        findings.push(Finding::new(
            "CSP-DIR-004",
            "Missing 'default-src' directive",
            Severity::Medium,
            "Without default-src, browsers use permissive defaults for unspecified resource types.",
            "Add 'default-src 'self'' as a baseline restriction.",
        ));
    }

    if !directives.contains_key("object-src") {
        findings.push(Finding::new(
            "CSP-DIR-005",
            "Missing 'object-src' directive",
            Severity::Medium,
            "Missing object-src allows plugin content (Flash, Silverlight) which can be exploited.",
            "Add 'object-src 'none'' to block plugin content.",
        ));
    }

    if !directives.contains_key("base-uri") {
        findings.push(Finding::new(
            "CSP-DIR-006",
            "Missing 'base-uri' directive",
            Severity::Low,
            "Missing base-uri allows injection of <base> tags to redirect relative URLs.",
            "Add 'base-uri 'self'' to restrict base URL injection.",
        ));
    }

    if !directives.contains_key("form-action") {
        findings.push(Finding::new(
            "CSP-DIR-007",
            "Missing 'form-action' directive",
            Severity::Low,
            "Missing form-action allows forms to submit to arbitrary endpoints.",
            "Add 'form-action 'self'' to restrict form submission targets.",
        ));
    }

    findings
}

fn validate_x_frame_options(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let val = match val {
        Some(v) => v,
        None => return (HeaderStatus::Missing, Some(Finding::new(
            "XFO-001",
            "Missing X-Frame-Options header",
            Severity::Medium,
            "X-Frame-Options prevents clickjacking by restricting iframe embedding.",
            "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
        ))),
    };

    let lower = val.trim().to_lowercase();
    if lower == "deny" || lower == "sameorigin" {
        (HeaderStatus::Optimal, None)
    } else if lower.starts_with("allow-from") {
        (
            HeaderStatus::Misconfigured,
            Some(Finding::new(
                "XFO-002",
                "X-Frame-Options uses deprecated ALLOW-FROM",
                Severity::Medium,
                "ALLOW-FROM is deprecated and unsupported in modern browsers, providing false confidence.",
                "Use CSP frame-ancestors directive instead of X-Frame-Options ALLOW-FROM.",
            ).with_detail(format!("Value: {val}"))),
        )
    } else {
        (
            HeaderStatus::Misconfigured,
            Some(Finding::new(
                "XFO-003",
                "X-Frame-Options has unrecognized value",
                Severity::Low,
                "Unrecognized X-Frame-Options values are ignored by browsers.",
                "Use DENY or SAMEORIGIN.",
            ).with_detail(format!("Value: {val}"))),
        )
    }
}

fn validate_x_content_type_options(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    match val {
        Some(v) if v.trim().to_lowercase() == "nosniff" => (HeaderStatus::Optimal, None),
        Some(v) => (
            HeaderStatus::Misconfigured,
            Some(Finding::new(
                "XCTO-001",
                "X-Content-Type-Options has incorrect value",
                Severity::Medium,
                "Only 'nosniff' is valid. Incorrect values are ignored, leaving MIME sniffing enabled.",
                "Set: X-Content-Type-Options: nosniff",
            ).with_detail(format!("Value: {v}"))),
        ),
        None => (
            HeaderStatus::Missing,
            Some(Finding::new(
                "XCTO-002",
                "Missing X-Content-Type-Options header",
                Severity::Medium,
                "Without nosniff, browsers may interpret files differently than declared (MIME confusion attacks).",
                "Add: X-Content-Type-Options: nosniff",
            )),
        ),
    }
}

fn validate_referrer_policy(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let valid_policies = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
        "origin-when-cross-origin",
    ];

    match val {
        Some(v) => {
            let lower = v.trim().to_lowercase();
            if lower == "unsafe-url" {
                (
                    HeaderStatus::Misconfigured,
                    Some(Finding::new(
                        "RP-001",
                        "Referrer-Policy set to unsafe-url",
                        Severity::High,
                        "unsafe-url sends full URL (including path/query) to any destination, leaking sensitive data.",
                        "Use 'strict-origin-when-cross-origin' or 'same-origin'.",
                    ).with_detail(format!("Value: {v}"))),
                )
            } else if valid_policies.contains(&lower.as_str()) {
                (HeaderStatus::Optimal, None)
            } else {
                (HeaderStatus::Misconfigured, Some(Finding::new(
                    "RP-002",
                    "Referrer-Policy has unrecognized value",
                    Severity::Low,
                    "Unrecognized values are ignored, falling back to browser defaults.",
                    "Use one of: no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin",
                ).with_detail(format!("Value: {v}"))))
            }
        }
        None => (
            HeaderStatus::Missing,
            Some(Finding::new(
                "RP-003",
                "Missing Referrer-Policy header",
                Severity::Low,
                "Without explicit policy, browser defaults may leak full URL paths to third parties.",
                "Add: Referrer-Policy: strict-origin-when-cross-origin",
            )),
        ),
    }
}

fn validate_permissions_policy(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    match val {
        Some(_) => (HeaderStatus::Optimal, None),
        None => (
            HeaderStatus::Missing,
            Some(Finding::new(
                "PP-001",
                "Missing Permissions-Policy header",
                Severity::Low,
                "Permissions-Policy restricts browser features (camera, mic, geolocation, etc.).",
                "Add a Permissions-Policy restricting unused features: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )),
        ),
    }
}

fn validate_coop(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let valid = ["same-origin", "same-origin-allow-popups", "unsafe-none"];
    match val {
        Some(v) if valid.contains(&v.trim().to_lowercase().as_str()) => (HeaderStatus::Optimal, None),
        Some(v) => (HeaderStatus::Misconfigured, Some(Finding::new(
            "COOP-001", "Cross-Origin-Opener-Policy has invalid value", Severity::Low,
            "Invalid COOP values are ignored by browsers.",
            "Use same-origin, same-origin-allow-popups, or unsafe-none",
        ).with_detail(format!("Value: {v}")))),
        None => (HeaderStatus::Missing, Some(Finding::new(
            "COOP-002", "Missing Cross-Origin-Opener-Policy header", Severity::Low,
            "COOP isolates browsing context to prevent cross-origin attacks (XS-Leaks).",
            "Add: Cross-Origin-Opener-Policy: same-origin",
        ))),
    }
}

fn validate_coep(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let valid = ["require-corp", "unsafe-none"];
    match val {
        Some(v) if valid.contains(&v.trim().to_lowercase().as_str()) => (HeaderStatus::Optimal, None),
        Some(v) => (HeaderStatus::Misconfigured, Some(Finding::new(
            "COEP-001", "Cross-Origin-Embedder-Policy has invalid value", Severity::Low,
            "Invalid COEP values are ignored by browsers.",
            "Use require-corp or unsafe-none",
        ).with_detail(format!("Value: {v}")))),
        None => (HeaderStatus::Missing, Some(Finding::new(
            "COEP-002", "Missing Cross-Origin-Embedder-Policy header", Severity::Low,
            "COEP prevents loading cross-origin resources without explicit permission.",
            "Add: Cross-Origin-Embedder-Policy: require-corp",
        ))),
    }
}

fn validate_corp(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let valid = ["same-origin", "cross-origin"];
    match val {
        Some(v) if valid.contains(&v.trim().to_lowercase().as_str()) => (HeaderStatus::Optimal, None),
        Some(v) => (HeaderStatus::Misconfigured, Some(Finding::new(
            "CORP-001", "Cross-Origin-Resource-Policy has invalid value", Severity::Low,
            "Invalid CORP values are ignored by browsers.",
            "Use same-origin or cross-origin",
        ).with_detail(format!("Value: {v}")))),
        None => (HeaderStatus::Missing, Some(Finding::new(
            "CORP-002", "Missing Cross-Origin-Resource-Policy header", Severity::Low,
            "CORP prevents other origins from reading resource responses.",
            "Add: Cross-Origin-Resource-Policy: same-origin",
        ))),
    }
}

fn validate_x_permitted_cross_domain_policies(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let valid = ["none", "master-only", "by-content-type", "by-ftp-filename", "all"];
    match val {
        Some(v) if valid.contains(&v.trim().to_lowercase().as_str()) => (HeaderStatus::Optimal, None),
        Some(v) => (HeaderStatus::Misconfigured, Some(Finding::new(
            "XPCD-001", "X-Permitted-Cross-Domain-Policies has invalid value", Severity::Low,
            "Invalid values are ignored, potentially leaving Flash/Silverlight cross-domain policies open.",
            "Use none (recommended), master-only, by-content-type, by-ftp-filename, or all",
        ).with_detail(format!("Value: {v}")))),
        None => (HeaderStatus::Missing, Some(Finding::new(
            "XPCD-002", "Missing X-Permitted-Cross-Domain-Policies header", Severity::Low,
            "Controls cross-domain policy files for Flash/Silverlight. Missing header defaults to permissive.",
            "Add: X-Permitted-Cross-Domain-Policies: none",
        ))),
    }
}

fn validate_x_dns_prefetch_control(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    let lower = val.map(|v| v.trim().to_lowercase());
    match lower.as_deref() {
        Some("off") => (HeaderStatus::Optimal, None),
        Some("on") => (
            HeaderStatus::PresentButWeak,
            Some(Finding::new(
                "XDPC-001",
                "DNS Prefetch Control explicitly enabled",
                Severity::Info,
                "DNS prefetch can leak domain lookups to the resolver. Consider disabling unless needed for performance.",
                "Add: X-DNS-Prefetch-Control: off",
            )),
        ),
        Some(v) => (HeaderStatus::Misconfigured, Some(Finding::new(
            "XDPC-002", "X-DNS-Prefetch-Control has invalid value", Severity::Low,
            "Invalid values are ignored.",
            "Use on or off",
        ).with_detail(format!("Value: {v}")))),
        None => (HeaderStatus::Missing, Some(Finding::new(
            "XDPC-003", "Missing X-DNS-Prefetch-Control header", Severity::Info,
            "Controls browser DNS prefetching. Not setting it is generally acceptable but explicit control is preferred.",
            "Consider adding: X-DNS-Prefetch-Control: off",
        ))),
    }
}

fn validate_clear_site_data(val: Option<&str>) -> (HeaderStatus, Option<Finding>) {
    match val {
        Some(v) if v.contains('"') || v.to_lowercase().contains("clear") => (HeaderStatus::Optimal, None),
        Some(v) => (HeaderStatus::Misconfigured, Some(Finding::new(
            "CSD-001", "Clear-Site-Data has unrecognized format", Severity::Low,
            "Clear-Site-Data should contain quoted directives like \"cache\", \"cookies\", \"storage\".",
            "Use: Clear-Site-Data: \"cache\", \"cookies\", \"storage\"",
        ).with_detail(format!("Value: {v}")))),
        None => (HeaderStatus::Missing, Some(Finding::new(
            "CSD-002", "Missing Clear-Site-Data header", Severity::Info,
            "Clear-Site-Data can be sent on logout to clear browser data. Its absence on auth pages is notable.",
            "Send Clear-Site-Data on logout endpoints: Clear-Site-Data: \"cache\", \"cookies\", \"storage\"",
        ))),
    }
}

// ============================================================
// 3. HTTP Method Testing
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct MethodProbe {
    pub method: String,
    pub status: Option<u16>,
    pub response_size: Option<usize>,
    pub risk: Option<String>,
}

pub fn probe_http_methods(_client: &Client, base_url: &Url) -> Vec<MethodProbe> {
    let methods = ["OPTIONS", "HEAD", "TRACE", "DELETE", "PUT", "PATCH"];
    let mut results = Vec::new();

    let no_redirect_client = match Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .user_agent("web-security-auditor/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => return results,
    };

    for method in &methods {
        let builder = match *method {
            "OPTIONS" => no_redirect_client.request(reqwest::Method::OPTIONS, base_url.as_str()),
            "HEAD" => no_redirect_client.head(base_url.as_str()),
            "TRACE" => no_redirect_client.request(reqwest::Method::from_bytes(b"TRACE").unwrap(), base_url.as_str()),
            "DELETE" => no_redirect_client.delete(base_url.as_str()),
            "PUT" => no_redirect_client.put(base_url.as_str()),
            "PATCH" => no_redirect_client.patch(base_url.as_str()),
            _ => continue,
        };

        let response = builder.send();
        let (status, response_size) = match response {
            Ok(resp) => {
                let st = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                (Some(st), Some(size))
            }
            Err(_) => (None, None),
        };

        let risk = assess_method_risk(method, status);
        results.push(MethodProbe {
            method: method.to_string(),
            status,
            response_size,
            risk,
        });
    }

    results
}

fn assess_method_risk(method: &str, status: Option<u16>) -> Option<String> {
    match (method, status) {
        ("TRACE", Some(s)) if (200..300).contains(&s) => {
            Some("TRACE enabled with 2xx response - potential Cross-Site Tracing (XST) risk".to_string())
        }
        ("TRACE", Some(s)) if (300..400).contains(&s) => {
            Some("TRACE redirected - may still be enabled on target".to_string())
        }
        ("DELETE", Some(s)) if (200..300).contains(&s) => {
            Some("DELETE accepted without apparent auth - potential data deletion risk".to_string())
        }
        ("PUT", Some(s)) if (200..300).contains(&s) => {
            Some("PUT accepted without apparent auth - potential file upload risk".to_string())
        }
        ("PATCH", Some(s)) if (200..300).contains(&s) => {
            Some("PATCH accepted - may allow resource modification".to_string())
        }
        ("OPTIONS", Some(s)) if (200..300).contains(&s) => {
            Some("OPTIONS reveals allowed methods via Allow header".to_string())
        }
        _ => None,
    }
}

// ============================================================
// 4. Enhanced Cookie Attribute Analysis
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct EnhancedCookieCheck {
    pub name: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub max_age: Option<i64>,
    pub expires: Option<String>,
    pub has_secure_prefix: bool,
    pub has_host_prefix: bool,
    pub is_sensitive_name: bool,
    pub findings: Vec<Finding>,
}

pub fn analyze_cookies_enhanced(headers: &reqwest::header::HeaderMap, is_https: bool) -> Vec<EnhancedCookieCheck> {
    let mut cookies = Vec::new();
    let sensitive_patterns = ["session", "token", "auth", "csrf", "jwt", "access", "refresh", "remember", "login", "user", "sid"];

    for header in headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(cookie_str) = header.to_str() {
            let parts: Vec<&str> = cookie_str.split(';').collect();
            if parts.is_empty() {
                continue;
            }

            let name_value = parts[0];
            let name = name_value.split('=').next().unwrap_or("").trim().to_string();
            if name.is_empty() {
                continue;
            }

            let lower_name = name.to_lowercase();
            let mut secure = false;
            let mut httponly = false;
            let mut samesite = None;
            let mut domain = None;
            let mut path = None;
            let mut max_age = None;
            let mut expires = None;

            for part in &parts[1..] {
                let trimmed = part.trim();
                let lowered = trimmed.to_lowercase();
                if lowered == "secure" {
                    secure = true;
                } else if lowered == "httponly" {
                    httponly = true;
                } else if lowered.starts_with("samesite=") {
                    samesite = Some(trimmed[9..].to_string());
                } else if lowered.starts_with("domain=") {
                    domain = Some(trimmed[7..].to_string());
                } else if lowered.starts_with("path=") {
                    path = Some(trimmed[5..].to_string());
                } else if lowered.starts_with("max-age=") {
                    max_age = trimmed[8..].parse::<i64>().ok();
                } else if lowered.starts_with("expires=") {
                    expires = Some(trimmed[8..].to_string());
                }
            }

            let has_secure_prefix = name.starts_with("__Secure-");
            let has_host_prefix = name.starts_with("__Host-");
            let is_sensitive_name = sensitive_patterns.iter().any(|p| lower_name.contains(*p));

            let mut findings = Vec::new();

            if is_sensitive_name && is_https && !secure {
                findings.push(Finding::new(
                    "COOKIE-001",
                    &format!("Sensitive cookie '{}' missing Secure flag", name),
                    Severity::High,
                    "Sensitive cookies without Secure flag can be transmitted over HTTP.",
                    "Add the Secure attribute to prevent transmission over unencrypted channels.",
                ).with_detail(format!("Cookie: {name}")));
            }

            if is_sensitive_name && !httponly {
                findings.push(Finding::new(
                    "COOKIE-002",
                    &format!("Sensitive cookie '{}' missing HttpOnly flag", name),
                    Severity::High,
                    "HttpOnly prevents JavaScript access to cookies. Without it, XSS can steal this cookie.",
                    "Add the HttpOnly attribute to prevent client-side script access.",
                ).with_detail(format!("Cookie: {name}")));
            }

            if samesite.is_none() {
                findings.push(Finding::new(
                    "COOKIE-003",
                    &format!("Cookie '{}' missing SameSite attribute", name),
                    Severity::Medium,
                    "SameSite protects against CSRF. Modern browsers default to Lax, but explicit is better.",
                    "Add SameSite=Strict or SameSite=Lax.",
                ).with_detail(format!("Cookie: {name}")));
            }

            if let Some(ma) = max_age {
                if ma > 86400 && is_sensitive_name {
                    findings.push(Finding::new(
                        "COOKIE-004",
                        &format!("Sensitive cookie '{}' has excessive Max-Age ({}s)", name, ma),
                        Severity::Medium,
                        "Long-lived session cookies increase the window for session hijacking.",
                        "Reduce Max-Age to <= 86400 (24 hours) for session cookies.",
                    ).with_detail(format!("Cookie: {name}, Max-Age: {ma}")));
                }
            }

            if let Some(ref dom) = domain {
                if dom.starts_with('.') {
                    findings.push(Finding::new(
                        "COOKIE-005",
                        &format!("Cookie '{}' has broad domain scope ({})", name, dom),
                        Severity::Low,
                        "Broad domain scope sends the cookie to all subdomains, increasing exposure.",
                        "Restrict domain scope unless cross-subdomain cookies are required.",
                    ).with_detail(format!("Cookie: {name}, Domain: {dom}")));
                }
            }

            if has_secure_prefix && !secure {
                findings.push(Finding::new(
                    "COOKIE-006",
                    &format!("Cookie '{}' has __Secure- prefix but missing Secure flag", name),
                    Severity::High,
                    "__Secure- prefix requires Secure flag per spec. Browser will reject this cookie.",
                    "Add the Secure attribute or remove the __Secure- prefix.",
                ).with_detail(format!("Cookie: {name}")));
            }

            if has_host_prefix && (!secure || path.as_deref() != Some("/") || domain.is_some()) {
                findings.push(Finding::new(
                    "COOKIE-007",
                    &format!("Cookie '{}' has __Host- prefix but violates requirements", name),
                    Severity::High,
                    "__Host- requires Secure flag, path=/, and no domain attribute. Browser will reject this cookie.",
                    "Ensure Secure flag, path=/, and no domain attribute, or remove the __Host- prefix.",
                ).with_detail(format!("Cookie: {name}")));
            }

            cookies.push(EnhancedCookieCheck {
                name,
                secure,
                httponly,
                samesite,
                domain,
                path,
                max_age,
                expires,
                has_secure_prefix,
                has_host_prefix,
                is_sensitive_name,
                findings,
            });
        }
    }

    cookies
}

// ============================================================
// 5. Enhanced TLS Configuration Checks
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct TlsConfigReport {
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub weak_cipher: bool,
    pub key_size: Option<usize>,
    pub signature_algorithm: Option<String>,
    pub validity_days: Option<i64>,
    pub is_self_signed: bool,
    pub hostname_mismatch: bool,
    pub findings: Vec<Finding>,
}

pub fn check_tls_config(url: &Url) -> TlsConfigReport {
    let mut findings = Vec::new();

    if url.scheme() != "https" {
        findings.push(Finding::new(
            "TLS-000",
            "Connection is not using HTTPS",
            Severity::Critical,
            "All traffic is transmitted in plaintext, enabling eavesdropping and tampering.",
            "Enable HTTPS with a valid TLS certificate.",
        ));
        return TlsConfigReport {
            protocol_version: None,
            cipher_suite: None,
            weak_cipher: false,
            key_size: None,
            signature_algorithm: None,
            validity_days: None,
            is_self_signed: false,
            hostname_mismatch: false,
            findings,
        };
    }

    let host = url.host_str().unwrap_or("localhost");
    let port = url.port().unwrap_or(443);

    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .ok()
        .map(|i| i.take(5).collect())
        .unwrap_or_default();

    // Test TLS 1.2 support using min protocol version
    let tls_1_2_supported = test_tls_version(&addrs, host, |builder| {
        builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).ok();
        builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).ok();
    });
    let tls_1_3_supported = test_tls_version(&addrs, host, |builder| {
        builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3)).ok();
        builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3)).ok();
    });

    if !tls_1_2_supported && !tls_1_3_supported {
        findings.push(Finding::new(
            "TLS-001",
            "No support for TLS 1.2 or 1.3",
            Severity::Critical,
            "Server does not support modern TLS versions. May be using deprecated protocols.",
            "Enable TLS 1.2 or TLS 1.3.",
        ));
    }

    let protocol_str = if tls_1_3_supported {
        "TLSv1.3"
    } else if tls_1_2_supported {
        "TLSv1.2"
    } else {
        "unknown"
    };

    let mut builder = SslConnector::builder(SslMethod::tls_client()).ok();
    if let Some(ref mut b) = builder {
        b.set_verify(SslVerifyMode::NONE);
    }

    let connector = builder.map(|b| b.build());

    let mut cipher_suite = None;
    let mut key_size = None;
    let mut sig_algo = None;
    let mut validity_days = None;
    let mut is_self_signed = false;
    let mut hostname_mismatch = false;
    let mut weak_cipher = false;

    if let Some(ref connector) = connector {
        for addr in &addrs {
            if let Ok(stream) = TcpStream::connect_timeout(addr, Duration::from_secs(5)) {
                if let Ok(ssl_stream) = connector.connect(host, stream) {
                    let ssl = ssl_stream.ssl();

                    cipher_suite = ssl.current_cipher().map(|c| c.name().to_string());

                    if let Some(cipher_name) = &cipher_suite {
                        let weak_ciphers = ["rc4", "des", "3des", "null", "exp", "md5"];
                        if weak_ciphers.iter().any(|wc| cipher_name.to_lowercase().contains(wc)) {
                            weak_cipher = true;
                            findings.push(Finding::new(
                                "TLS-002",
                                "Weak cipher suite detected",
                                Severity::High,
                                &format!("Cipher '{cipher_name}' is considered weak and vulnerable to known attacks."),
                                "Configure server to use only strong ciphers (AES-GCM, ChaCha20-Poly1305).",
                            ).with_detail(format!("Cipher: {cipher_name}")));
                        }
                    }

                    if let Some(cert) = ssl.peer_certificate() {
                        // Check key size
                        if let Ok(pkey) = cert.public_key() {
                            let size = pkey.size();
                            key_size = Some((size * 8) as usize);
                            if size * 8 < 2048 {
                                findings.push(Finding::new(
                                    "TLS-003",
                                    "Weak certificate key size",
                                    Severity::High,
                                    &format!("Key size {} bits is below recommended minimum of 2048 bits.", size * 8),
                                    "Use RSA keys >= 2048 bits (4096 recommended).",
                                ).with_detail(format!("Key size: {} bits", size * 8)));
                            }
                        }

                        // Check signature algorithm
                        let sig_nid = cert.signature_algorithm().object().nid();
                        sig_algo = Some(sig_nid.long_name().unwrap_or("unknown").to_string());
                        let sha1_nids = [
                            openssl::nid::Nid::SHA1WITHRSAENCRYPTION,
                            openssl::nid::Nid::SHA1WITHRSA,
                            openssl::nid::Nid::DSAWITHSHA1,
                        ];
                        if sha1_nids.contains(&sig_nid) {
                            findings.push(Finding::new(
                                "TLS-004",
                                "Certificate uses deprecated SHA-1 signature",
                                Severity::Medium,
                                "SHA-1 signatures are vulnerable to collision attacks.",
                                "Reissue certificate with SHA-256 or stronger signature algorithm.",
                            ).with_detail(format!("Algorithm: {}", sig_algo.as_ref().unwrap())));
                        }

                        // Check validity period
                        let not_after = cert.not_after().to_string();
                        let not_before = cert.not_before().to_string();
                        if let (Ok(after_dt), Ok(before_dt)) = (
                            chrono::DateTime::parse_from_rfc3339(&not_after),
                            chrono::DateTime::parse_from_rfc3339(&not_before),
                        ) {
                            let total_days = (after_dt - before_dt).num_days();
                            validity_days = Some(total_days);
                            if total_days > 398 {
                                findings.push(Finding::new(
                                    "TLS-005",
                                    "Certificate validity period exceeds 398 days",
                                    Severity::Low,
                                    &format!("Validity period is {} days, exceeding the CA/B Forum guideline of 398 days.", total_days),
                                    "Use certificates with validity periods <= 398 days.",
                                ).with_detail(format!("Validity: {} days", total_days)));
                            }
                        }

                        // Check self-signed
                        let subject = cert.subject_name().to_der().ok();
                        let issuer = cert.issuer_name().to_der().ok();
                        if subject == issuer {
                            is_self_signed = true;
                            findings.push(Finding::new(
                                "TLS-006",
                                "Certificate appears to be self-signed",
                                Severity::Medium,
                                "Self-signed certificates are not trusted by browsers and may indicate a testing or misconfigured environment.",
                                "Use a certificate signed by a trusted CA (e.g., Let's Encrypt).",
                            ));
                        }

                        // Check hostname match
                        let cn = cert.subject_name()
                            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                            .next()
                            .and_then(|e| e.data().as_utf8().ok());

                        let san_names: Vec<String> = cert.subject_alt_names()
                            .map(|names| names.iter().filter_map(|n| n.dnsname().map(|s| s.to_string())).collect())
                            .unwrap_or_default();

                        let host_matches = cn.as_ref().map(|c| c.to_string() == host).unwrap_or(false)
                            || san_names.iter().any(|s| s == host || s.starts_with("*."));

                        if !host_matches {
                            hostname_mismatch = true;
                            findings.push(Finding::new(
                                "TLS-007",
                                "Certificate hostname mismatch",
                                Severity::High,
                                "Certificate CN/SANs do not match the requested hostname. This may indicate a misconfiguration or MITM.",
                                "Ensure the certificate includes the requested hostname in CN or SANs.",
                            ).with_detail(format!("Requested: {host}, SANs: {}", san_names.join(", "))));
                        }
                    }

                    break;
                }
            }
        }
    }

    TlsConfigReport {
        protocol_version: Some(protocol_str.to_string()),
        cipher_suite,
        weak_cipher,
        key_size,
        signature_algorithm: sig_algo,
        validity_days,
        is_self_signed,
        hostname_mismatch,
        findings,
    }
}

fn test_tls_version<F>(addrs: &[SocketAddr], host: &str, configure: F) -> bool
where
    F: Fn(&mut openssl::ssl::SslConnectorBuilder),
{
    let mut builder = match SslConnector::builder(SslMethod::tls_client()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    builder.set_verify(SslVerifyMode::NONE);
    configure(&mut builder);
    let connector = builder.build();

    for addr in addrs {
        if let Ok(stream) = TcpStream::connect_timeout(addr, Duration::from_secs(3)) {
            if connector.connect(host, stream).is_ok() {
                return true;
            }
        }
    }
    false
}

// ============================================================
// 6. Cache Control Analysis
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct CacheControlReport {
    pub cache_control: Option<String>,
    pub pragma: Option<String>,
    pub expires: Option<String>,
    pub has_no_store: bool,
    pub has_no_cache: bool,
    pub has_private: bool,
    pub has_must_revalidate: bool,
    pub findings: Vec<Finding>,
}

pub fn analyze_cache_control(headers: &reqwest::header::HeaderMap, has_set_cookie: bool) -> CacheControlReport {
    let mut findings = Vec::new();

    let cache_control = headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let pragma = headers
        .get("pragma")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let expires = headers
        .get("expires")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let cc_lower = cache_control.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
    let has_no_store = cc_lower.contains("no-store");
    let has_no_cache = cc_lower.contains("no-cache");
    let has_private = cc_lower.contains("private");
    let has_must_revalidate = cc_lower.contains("must-revalidate");

    // Auth pages should have cache control
    if has_set_cookie && !has_no_store && !has_no_cache {
        findings.push(Finding::new(
            "CACHE-001",
            "Authenticated response missing cache-control no-store",
            Severity::Medium,
            "Responses with Set-Cookie should include no-store or no-cache to prevent caching sensitive authenticated data.",
            "Add: Cache-Control: no-store, no-cache, must-revalidate, private",
        ));
    }

    if has_set_cookie && !has_private {
        findings.push(Finding::new(
            "CACHE-002",
            "Authenticated response missing 'private' cache directive",
            Severity::Low,
            "Authenticated content should use 'private' to prevent shared cache storage.",
            "Add 'private' to Cache-Control directive.",
        ));
    }

    if let Some(ref pragma_val) = pragma {
        if pragma_val.to_lowercase() != "no-cache" && !has_no_cache && !has_no_store {
            findings.push(Finding::new(
                "CACHE-003",
                "Pragma header present but not set to no-cache",
                Severity::Info,
                "Legacy Pragma header should be 'no-cache' if used. Modern Cache-Control is preferred.",
                "Use Cache-Control instead of Pragma for HTTP/1.1 clients.",
            ).with_detail(format!("Pragma: {pragma_val}")));
        }
    }

    CacheControlReport {
        cache_control,
        pragma,
        expires,
        has_no_store,
        has_no_cache,
        has_private,
        has_must_revalidate,
        findings,
    }
}

// ============================================================
// 7. Mixed Content Detection
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct MixedContentFinding {
    pub element_type: String,
    pub url: String,
    pub severity: Severity, // Critical for active, Medium for passive
}

pub fn detect_mixed_content(html_body: &str, base_url: &Url) -> Vec<MixedContentFinding> {
    let mut results = Vec::new();
    let base_scheme = base_url.scheme();

    if base_scheme != "https" {
        return results; // Mixed content only matters on HTTPS pages
    }

    // Active mixed content patterns (critical)
    let active_patterns = [
        (r#"<script[^>]+src=["']http://[^"']+["']"#, "script"),
        (r#"<link[^>]+href=["']http://[^"']+["']"#, "stylesheet"),
        (r#"<iframe[^>]+src=["']http://[^"']+["']"#, "iframe"),
        (r#"<object[^>]+data=["']http://[^"']+["']"#, "object"),
        (r#"<embed[^>]+src=["']http://[^"']+["']"#, "embed"),
        (r#"<form[^>]+action=["']http://[^"']+["']"#, "form"),
    ];

    // Passive mixed content patterns (warning)
    let passive_patterns = [
        (r#"<img[^>]+src=["']http://[^"']+["']"#, "image"),
        (r#"<audio[^>]+src=["']http://[^"']+["']"#, "audio"),
        (r#"<video[^>]+src=["']http://[^"']+["']"#, "video"),
        (r#"<source[^>]+src=["']http://[^"']+["']"#, "source"),
    ];

    for (pattern, element_type) in &active_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.find_iter(html_body) {
                let matched = cap.as_str();
                if let Some(url) = extract_http_url(matched) {
                    results.push(MixedContentFinding {
                        element_type: element_type.to_string(),
                        url: url.to_string(),
                        severity: Severity::Critical,
                    });
                }
            }
        }
    }

    for (pattern, element_type) in &passive_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.find_iter(html_body) {
                let matched = cap.as_str();
                if let Some(url) = extract_http_url(matched) {
                    results.push(MixedContentFinding {
                        element_type: element_type.to_string(),
                        url: url.to_string(),
                        severity: Severity::Medium,
                    });
                }
            }
        }
    }

    results
}

fn extract_http_url(html_snippet: &str) -> Option<String> {
    let start = html_snippet.find("http://")?;
    let rest = &html_snippet[start..];
    let end = rest.find(|c: char| c == '"' || c == '\'' || c == '>' || c.is_whitespace())?;
    Some(rest[..end].to_string())
}

// ============================================================
// 8. Information Disclosure Detection
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct InfoDisclosureReport {
    pub disclosing_headers: Vec<InfoDisclosure>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InfoDisclosure {
    pub header: String,
    pub value: String,
    pub disclosure_type: String,
    pub severity: Severity,
}

pub fn detect_information_disclosure(headers: &reqwest::header::HeaderMap) -> InfoDisclosureReport {
    let mut disclosing = Vec::new();

    let version_pattern = Regex::new(r"\d+\.\d+").unwrap();

    let disclosure_headers = [
        ("server", "Server version disclosure"),
        ("x-powered-by", "Framework version disclosure"),
        ("x-aspnet-version", "ASP.NET version disclosure"),
        ("x-aspnetmvc-version", "ASP.NET MVC version disclosure"),
        ("x-runtime", "Framework runtime timing disclosure"),
        ("x-version", "Application version disclosure"),
    ];

    for (header_name, disclosure_type) in &disclosure_headers {
        if let Some(val) = headers.get(*header_name).and_then(|v| v.to_str().ok()) {
            if version_pattern.is_match(val) {
                disclosing.push(InfoDisclosure {
                    header: header_name.to_string(),
                    value: val.to_string(),
                    disclosure_type: disclosure_type.to_string(),
                    severity: Severity::Low,
                });
            }
        }
    }

    // Check for debug headers
    let debug_prefixes = ["x-debug", "x-profiler", "x-trace", "x-request-debug"];
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if debug_prefixes.iter().any(|p| name_lower.starts_with(p)) {
            if let Ok(val) = value.to_str() {
                disclosing.push(InfoDisclosure {
                    header: name.as_str().to_string(),
                    value: val.to_string(),
                    disclosure_type: "Debug header present".to_string(),
                    severity: Severity::Medium,
                });
            }
        }
    }

    // Check for internal IP leakage
    let ip_pattern = Regex::new(r"10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+").unwrap();
    for (name, value) in headers.iter() {
        if let Ok(val) = value.to_str() {
            if ip_pattern.is_match(val) {
                disclosing.push(InfoDisclosure {
                    header: name.as_str().to_string(),
                    value: val.to_string(),
                    disclosure_type: "Internal IP address leakage".to_string(),
                    severity: Severity::Medium,
                });
            }
        }
    }

    InfoDisclosureReport {
        disclosing_headers: disclosing,
    }
}

// ============================================================
// 9. Enhanced CORS Preflight Analysis
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct CorsPreflightReport {
    pub allow_origin: Option<String>,
    pub allow_methods: Option<String>,
    pub allow_headers: Option<String>,
    pub allow_credentials: Option<String>,
    pub max_age: Option<String>,
    pub vary_origin: bool,
    pub origin_reflection: bool,
    pub wildcard_with_credentials: bool,
    pub excessive_max_age: bool,
    pub findings: Vec<Finding>,
}

pub fn analyze_cors_preflight(client: &Client, base_url: &Url) -> CorsPreflightReport {
    let mut findings = Vec::new();
    let test_origin = "https://evil.example.com";

    let response = match client
        .request(reqwest::Method::OPTIONS, base_url.as_str())
        .header("Origin", test_origin)
        .header("Access-Control-Request-Method", "GET")
        .header("Access-Control-Request-Headers", "Content-Type")
        .timeout(Duration::from_secs(10))
        .send()
    {
        Ok(r) => r,
        Err(_) => {
            return CorsPreflightReport {
                allow_origin: None,
                allow_methods: None,
                allow_headers: None,
                allow_credentials: None,
                max_age: None,
                vary_origin: false,
                origin_reflection: false,
                wildcard_with_credentials: false,
                excessive_max_age: false,
                findings: vec![Finding::new(
                    "CORS-PREFLIGHT-001",
                    "CORS preflight request failed",
                    Severity::Info,
                    "Could not complete CORS preflight check. Server may not support CORS or may be down.",
                    "N/A",
                )],
            }
        }
    };

    let headers = response.headers();

    let allow_origin = headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let allow_methods = headers
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let allow_headers = headers
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let allow_credentials = headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let max_age = headers
        .get("access-control-max-age")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let origin_reflection = allow_origin.as_ref().map(|v| v == test_origin).unwrap_or(false);
    let wildcard = allow_origin.as_ref().map(|v| v == "*").unwrap_or(false);
    let wildcard_with_credentials = wildcard && allow_credentials.as_ref().map(|v| v.to_lowercase() == "true").unwrap_or(false);

    let vary_header = headers.get("vary").and_then(|v| v.to_str().ok()).unwrap_or("");
    let vary_origin = vary_header.to_lowercase().split(',').any(|v| v.trim() == "origin");

    let excessive_max_age = max_age
        .as_ref()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|v| v > 600)
        .unwrap_or(false);

    if wildcard_with_credentials {
        findings.push(Finding::new(
            "CORS-001",
            "CORS allows wildcard origin with credentials",
            Severity::Critical,
            "Access-Control-Allow-Origin: * combined with Allow-Credentials: true allows any site to read responses with credentials.",
            "Remove wildcard origin or disable credentials. Use specific origins instead.",
        ));
    }

    if origin_reflection && allow_credentials.as_ref().map(|v| v.to_lowercase() == "true").unwrap_or(false) {
        findings.push(Finding::new(
            "CORS-002",
            "CORS reflects arbitrary origin with credentials",
            Severity::High,
            "Server reflects the test origin, allowing any domain to make credentialed requests.",
            "Use a fixed allowlist of trusted origins instead of reflection.",
        ));
    }

    if !vary_origin && allow_origin.is_some() {
        findings.push(Finding::new(
            "CORS-003",
            "CORS response missing Vary: Origin header",
            Severity::Medium,
            "Without Vary: Origin, caches may serve responses intended for one origin to another.",
            "Add Vary: Origin to CORS responses.",
        ));
    }

    if excessive_max_age {
        findings.push(Finding::new(
            "CORS-004",
            "Excessive Access-Control-Max-Age",
            Severity::Low,
            "Long preflight cache times may cause stale preflight responses after CORS policy changes.",
            "Set Access-Control-Max-Age to a reasonable value (<= 600 seconds).",
        ).with_detail(format!("Max-Age: {}", max_age.as_ref().unwrap())));
    }

    CorsPreflightReport {
        allow_origin,
        allow_methods,
        allow_headers,
        allow_credentials,
        max_age,
        vary_origin,
        origin_reflection,
        wildcard_with_credentials,
        excessive_max_age,
        findings,
    }
}

// ============================================================
// 10. HSTS Preload Eligibility
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct HstsPreloadReport {
    pub hsts_present: bool,
    pub hsts_value: Option<String>,
    pub sufficient_max_age: bool,
    pub has_include_subdomains: bool,
    pub has_preload: bool,
    pub preload_eligible: bool,
}

pub fn check_hsts_preload(headers: &reqwest::header::HeaderMap) -> HstsPreloadReport {
    let hsts_value = headers
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    if let Some(ref val) = hsts_value {
        let lower = val.to_lowercase();
        let max_age = extract_hsts_max_age(val);
        let has_include_subdomains = lower.contains("includesubdomains");
        let has_preload = lower.contains("preload");
        let sufficient_max_age = max_age >= 31536000;

        HstsPreloadReport {
            hsts_present: true,
            hsts_value: Some(val.clone()),
            sufficient_max_age,
            has_include_subdomains,
            has_preload,
            preload_eligible: sufficient_max_age && has_include_subdomains && has_preload,
        }
    } else {
        HstsPreloadReport {
            hsts_present: false,
            hsts_value: None,
            sufficient_max_age: false,
            has_include_subdomains: false,
            has_preload: false,
            preload_eligible: false,
        }
    }
}

// ============================================================
// 11. Clickjacking Protection Validation
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct ClickjackingReport {
    pub x_frame_options: Option<String>,
    pub csp_frame_ancestors: bool,
    pub protected: bool,
    pub findings: Vec<Finding>,
}

pub fn check_clickjacking_protection(headers: &reqwest::header::HeaderMap) -> ClickjackingReport {
    let mut findings = Vec::new();

    let xfo = headers
        .get("x-frame-options")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let has_frame_ancestors = csp.to_lowercase().contains("frame-ancestors");

    let xfo_valid = xfo.as_ref().map(|v| {
        let lower = v.trim().to_lowercase();
        lower == "deny" || lower == "sameorigin"
    }).unwrap_or(false);

    let protected = xfo_valid || has_frame_ancestors;

    if !protected {
        findings.push(Finding::new(
            "CLICK-001",
            "Missing clickjacking protection",
            Severity::Medium,
            "Neither X-Frame-Options nor CSP frame-ancestors is set. The site can be embedded in iframes for clickjacking.",
            "Add X-Frame-Options: DENY or CSP: frame-ancestors 'self'",
        ));
    }

    if let Some(ref v) = xfo {
        if v.trim().to_lowercase().starts_with("allow-from") {
            findings.push(Finding::new(
                "CLICK-002",
                "X-Frame-Options uses deprecated ALLOW-FROM",
                Severity::Medium,
                "ALLOW-FROM is unsupported in modern browsers and provides false confidence.",
                "Use CSP frame-ancestors instead.",
            ).with_detail(format!("Value: {v}")));
        }
    }

    if xfo_valid && has_frame_ancestors {
        findings.push(Finding::new(
            "CLICK-003",
            "Redundant clickjacking protection",
            Severity::Info,
            "Both X-Frame-Options and CSP frame-ancestors are present. CSP is sufficient; X-Frame-Options is legacy.",
            "Consider using only CSP frame-ancestors for modern browsers.",
        ));
    }

    ClickjackingReport {
        x_frame_options: xfo,
        csp_frame_ancestors: has_frame_ancestors,
        protected,
        findings,
    }
}

// ============================================================
// 12. HTTP/2 and HTTP/3 Support Detection
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolSupportReport {
    pub http_version: Option<String>,
    pub http2_supported: bool,
    pub http3_supported: bool,
    pub alt_svc: Option<String>,
}

pub fn check_protocol_support(client: &Client, base_url: &Url) -> ProtocolSupportReport {
    let response = match client.get(base_url.as_str()).send() {
        Ok(r) => r,
        Err(_) => {
            return ProtocolSupportReport {
                http_version: None,
                http2_supported: false,
                http3_supported: false,
                alt_svc: None,
            }
        }
    };

    let version = response.version();
    let http_version = match version {
        reqwest::Version::HTTP_09 => Some("HTTP/0.9".to_string()),
        reqwest::Version::HTTP_10 => Some("HTTP/1.0".to_string()),
        reqwest::Version::HTTP_11 => Some("HTTP/1.1".to_string()),
        reqwest::Version::HTTP_2 => Some("HTTP/2".to_string()),
        reqwest::Version::HTTP_3 => Some("HTTP/3".to_string()),
        _ => None,
    };

    let http2_supported = version == reqwest::Version::HTTP_2;

    let alt_svc = response.headers()
        .get("alt-svc")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let http3_supported = alt_svc.as_ref().map(|v| v.contains("h3")).unwrap_or(false);

    ProtocolSupportReport {
        http_version,
        http2_supported,
        http3_supported,
        alt_svc,
    }
}

// ============================================================
// 13. robots.txt/sitemap Security Review
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct RobotsReviewReport {
    pub disallowed_paths: Vec<String>,
    pub sensitive_paths: Vec<String>,
}

pub fn review_robots_txt(body: &str) -> RobotsReviewReport {
    let sensitive_patterns = [
        "/admin", "/backup", "/staging", "/internal", "/.env", "/config",
        "/debug", "/test", "/temp", "/private", "/secret", "/db", "/database",
        "/sql", "/logs", "/log", "/api/internal", "/api/admin", "/.git",
        "/.svn", "/wp-config", "/xmlrpc", "/server-status", "/server-info",
    ];

    let disallowed: Vec<String> = body
        .lines()
        .filter(|line| line.trim().to_lowercase().starts_with("disallow:"))
        .filter_map(|line| {
            let path = line.trim()["disallow:".len()..].trim().to_string();
            if !path.is_empty() { Some(path) } else { None }
        })
        .collect();

    let sensitive: Vec<String> = disallowed
        .iter()
        .filter(|path| {
            let lower = path.to_lowercase();
            sensitive_patterns.iter().any(|pat| lower.starts_with(pat) || lower.contains(pat))
        })
        .cloned()
        .collect();

    RobotsReviewReport {
        disallowed_paths: disallowed,
        sensitive_paths: sensitive,
    }
}

// ============================================================
// 14. security.txt Discovery and Validation (RFC 9116)
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct SecurityTxtReport {
    pub present: bool,
    pub fields: HashMap<String, String>,
    pub has_contact: bool,
    pub has_expires: bool,
    pub expires_valid: bool,
    pub findings: Vec<Finding>,
}

pub fn validate_security_txt(body: &str) -> SecurityTxtReport {
    let mut findings = Vec::new();
    let mut fields: HashMap<String, String> = HashMap::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            fields.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    let has_contact = fields.contains_key("contact");
    let has_expires = fields.contains_key("expires");

    let expires_valid = fields.get("expires").and_then(|v| {
        chrono::DateTime::parse_from_rfc2822(v)
            .map(|dt| dt > chrono::DateTime::<chrono::Utc>::from(chrono::Utc::now()))
            .ok()
    }).unwrap_or(false);

    if !has_contact {
        findings.push(Finding::new(
            "SECTXT-001",
            "security.txt missing Contact field",
            Severity::Medium,
            "RFC 9116 requires a Contact field for vulnerability reporting. Without it, researchers cannot easily report security issues.",
            "Add: Contact: mailto:security@example.com or Contact: https://example.com/security-reporting",
        ));
    }

    if !has_expires {
        findings.push(Finding::new(
            "SECTXT-002",
            "security.txt missing Expires field",
            Severity::Low,
            "RFC 9116 requires an Expires field to indicate when the file should be re-fetched.",
            "Add: Expires: 2025-12-31T23:59:59.000Z",
        ));
    }

    if has_expires && !expires_valid {
        findings.push(Finding::new(
            "SECTXT-003",
            "security.txt has expired or invalid Expires field",
            Severity::Medium,
            "An expired security.txt suggests the information may be outdated.",
            "Update the Expires field to a future date.",
        ));
    }

    SecurityTxtReport {
        present: true,
        fields,
        has_contact,
        has_expires,
        expires_valid,
        findings,
    }
}

// ============================================================
// 15. Subresource Integrity (SRI) Check
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct SriReport {
    pub resources_checked: usize,
    pub missing_integrity: Vec<String>,
}

pub fn check_subresource_integrity(html_body: &str, base_url: &Url) -> SriReport {
    let mut missing = Vec::new();
    let mut checked = 0;

    let base_host = base_url.host_str().unwrap_or("");
    let base_port = base_url.port();

    // Check script tags
    let script_re = Regex::new(r#"<script[^>]+src=["']([^"']+)["'][^>]*>"#).unwrap();
    for cap in script_re.captures_iter(html_body) {
        if let Some(src) = cap.get(1) {
            checked += 1;
            let full_tag = cap.get(0).unwrap().as_str();
            if !full_tag.contains("integrity=") && is_cross_origin(src.as_str(), base_host, base_port) {
                missing.push(src.as_str().to_string());
            }
        }
    }

    // Check stylesheet link tags
    let link_re = Regex::new(r#"<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["'][^>]*>|<link[^>]+href=["']([^"']+)["'][^>]+rel=["']stylesheet["'][^>]*>"#).unwrap();
    for cap in link_re.captures_iter(html_body) {
        let src = cap.get(1).or_else(|| cap.get(2));
        if let Some(src_match) = src {
            checked += 1;
            let full_tag = cap.get(0).unwrap().as_str();
            if !full_tag.contains("integrity=") && is_cross_origin(src_match.as_str(), base_host, base_port) {
                missing.push(src_match.as_str().to_string());
            }
        }
    }

    SriReport {
        resources_checked: checked,
        missing_integrity: missing,
    }
}

fn is_cross_origin(url_str: &str, base_host: &str, base_port: Option<u16>) -> bool {
    if url_str.starts_with("//") || url_str.starts_with("http://") || url_str.starts_with("https://") {
        if let Ok(parsed) = Url::parse(url_str) {
            let url_host = parsed.host_str().unwrap_or("");
            let url_port = parsed.port();

            if url_host != base_host {
                return true;
            }

            let effective_base_port = base_port.or_else(|| match parsed.scheme() {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            });

            if effective_base_port != url_port {
                return true;
            }

            return false;
        }

        // If it's an absolute URL we can't parse, assume cross-origin
        return true;
    }

    // Relative URL - same origin
    false
}
