use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use reqwest::blocking::Client;
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use url::Url;

use crate::security_checks::{
    analyze_cache_control, analyze_csp_directives, analyze_cookies_enhanced, analyze_cors_preflight,
    analyze_security_headers, check_clickjacking_protection, check_hsts_preload,
    check_protocol_support, check_subresource_integrity, check_tls_config, detect_information_disclosure,
    detect_mixed_content, probe_http_methods, review_robots_txt, validate_security_txt,
    CacheControlReport, ClickjackingReport, CorsPreflightReport, EnhancedCookieCheck,
    Finding, HeaderFinding, HstsPreloadReport, InfoDisclosureReport, MethodProbe,
    ProtocolSupportReport, RobotsReviewReport, SecurityTxtReport, Severity, SriReport, TlsConfigReport,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Unresolved,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Unresolved => write!(f, "unresolved"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebReport {
    pub final_url: String,
    pub status: u16,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub content_type: Option<String>,
    pub security_headers: Vec<HeaderCheck>,
    pub security_header_findings: Vec<HeaderFinding>,
    pub csp_findings: Vec<Finding>,
    pub robots_txt_present: bool,
    pub sitemap_present: bool,
    pub tls: TlsInfo,
    pub tls_config: TlsConfigReport,
    pub redirects: Vec<RedirectHop>,
    pub cookies: Vec<CookieCheck>,
    pub enhanced_cookies: Vec<EnhancedCookieCheck>,
    pub cors: CorsCheck,
    pub cors_preflight: CorsPreflightReport,
    pub tech: TechFingerprint,
    pub method_probes: Vec<MethodProbe>,
    pub cache_control: CacheControlReport,
    pub mixed_content: Vec<crate::security_checks::MixedContentFinding>,
    pub info_disclosure: InfoDisclosureReport,
    pub hsts_preload: HstsPreloadReport,
    pub clickjacking: ClickjackingReport,
    pub protocol_support: ProtocolSupportReport,
    pub robots_review: Option<RobotsReviewReport>,
    pub security_txt: Option<SecurityTxtReport>,
    pub sri: Option<SriReport>,
    pub all_findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderCheck {
    pub name: &'static str,
    pub present: bool,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    pub enabled: bool,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub expiry: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub san: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedirectHop {
    pub index: usize,
    pub from_url: String,
    pub to_url: String,
    pub status: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieCheck {
    pub name: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorsCheck {
    pub header_present: bool,
    pub allow_origin: Option<String>,
    pub allow_credentials: Option<String>,
    pub wildcard_origin: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TechFingerprint {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub detected_technologies: Vec<String>,
}

pub fn scan_ports(host: &str, ports: &[u16], timeout: Duration, workers: usize) -> Vec<PortResult> {
    let worker_count = worker_count_for_len(workers, ports.len());
    let queue: Arc<Mutex<VecDeque<(usize, u16)>>> =
        Arc::new(Mutex::new(ports.iter().copied().enumerate().collect()));
    let host = Arc::new(host.to_string());
    let results = Arc::new(Mutex::new(vec![None; ports.len()]));

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let host = Arc::clone(&host);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || loop {
            let job = {
                let mut queue = queue.lock().expect("port queue lock poisoned");
                queue.pop_front()
            };

            let Some((index, port)) = job else {
                break;
            };

            let state = resolve_socket_addrs(&host, port)
                .map(|mut addrs| {
                    addrs
                        .find(|addr| TcpStream::connect_timeout(addr, timeout).is_ok())
                        .map(|_| PortState::Open)
                        .unwrap_or(PortState::Closed)
                })
                .unwrap_or(PortState::Unresolved);

            let mut results = results.lock().expect("port results lock poisoned");
            results[index] = Some(PortResult { port, state });
        }));
    }

    for handle in handles {
        handle.join().expect("port scan worker panicked");
    }

    Arc::try_unwrap(results)
        .expect("port results still referenced")
        .into_inner()
        .expect("port results lock poisoned")
        .into_iter()
        .flatten()
        .collect()
}

pub fn web_probe(client: &Client, base_url: &Url) -> Result<WebReport> {
    let response = client
        .get(base_url.as_str())
        .send()
        .with_context(|| format!("request failed for {}", base_url))?;

    let final_url = response.url().to_string();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body_text = response.text().unwrap_or_default();

    // Basic security headers (legacy format for backward compat)
    let security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    .into_iter()
    .map(|name| HeaderCheck {
        name,
        present: headers.contains_key(name),
        value: headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
    })
    .collect();

    let robots_url = base_url.join("robots.txt").ok();
    let sitemap_url = base_url.join("sitemap.xml").ok();
    let security_txt_url = base_url.join(".well-known/security.txt").ok();
    let robots_client = client.clone();
    let sitemap_client = client.clone();
    let sectxt_client = client.clone();

    let robots_handle = thread::spawn(move || match robots_url {
        Some(url) => fetch_resource_text(&robots_client, &url),
        None => None,
    });
    let sitemap_handle = thread::spawn(move || match sitemap_url {
        Some(url) => is_public_resource_present(&sitemap_client, &url),
        None => false,
    });
    let sectxt_handle = thread::spawn(move || match security_txt_url {
        Some(url) => fetch_resource_text(&sectxt_client, &url),
        None => None,
    });

    // Professional security checks
    let security_header_findings = analyze_security_headers(&headers);
    let csp_findings = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|v| analyze_csp_directives(v))
        .unwrap_or_default();
    let tls = inspect_tls_info(base_url);
    let tls_config = check_tls_config(base_url);
    let redirects = extract_redirect_chain(client, base_url);
    let cookies = analyze_cookies(&headers);
    let is_https = base_url.scheme() == "https";
    let enhanced_cookies = analyze_cookies_enhanced(&headers, is_https);
    let cors = check_cors_headers(&headers);
    let cors_preflight = analyze_cors_preflight(client, base_url);
    let tech = fingerprint_technologies(&headers);
    let method_probes = probe_http_methods(client, base_url);
    let has_set_cookie = headers.contains_key(reqwest::header::SET_COOKIE);
    let cache_control = analyze_cache_control(&headers, has_set_cookie);
    let mixed_content = detect_mixed_content(&body_text, base_url);
    let info_disclosure = detect_information_disclosure(&headers);
    let hsts_preload = check_hsts_preload(&headers);
    let clickjacking = check_clickjacking_protection(&headers);
    let protocol_support = check_protocol_support(client, base_url);

    let robots_txt_result = robots_handle.join().expect("robots probe thread panicked");
    let robots_review = robots_txt_result.as_ref().map(|body| review_robots_txt(body));
    let security_txt_result = sectxt_handle.join().expect("security.txt probe thread panicked");
    let security_txt_report = security_txt_result.as_ref().map(|body| validate_security_txt(body));

    // SRI check
    let sri = if body_text.contains("<script") || body_text.contains("<link") {
        Some(check_subresource_integrity(&body_text, base_url))
    } else {
        None
    };

    // Aggregate all findings
    let mut all_findings = Vec::new();
    for hf in &security_header_findings {
        if let Some(ref f) = hf.finding {
            all_findings.push(f.clone());
        }
    }
    all_findings.extend(csp_findings.clone());
    all_findings.extend(tls_config.findings.clone());
    for ec in &enhanced_cookies {
        all_findings.extend(ec.findings.clone());
    }
    all_findings.extend(cors_preflight.findings.clone());
    all_findings.extend(cache_control.findings.clone());
    all_findings.extend(clickjacking.findings.clone());
    if let Some(ref st) = security_txt_report {
        all_findings.extend(st.findings.clone());
    }

    // Add method risks as findings
    for mp in &method_probes {
        if let Some(ref risk) = mp.risk {
            let sev = if risk.contains("Critical") || risk.contains("deletion") || risk.contains("upload") {
                Severity::High
            } else {
                Severity::Medium
            };
            all_findings.push(Finding::new(
                &format!("METHOD-{}", mp.method),
                &format!("HTTP {} method risk", mp.method),
                sev,
                risk,
                "Review and disable unnecessary HTTP methods on the server.",
            ).with_detail(format!("Method: {}, Status: {:?}", mp.method, mp.status)));
        }
    }

    // Add info disclosure findings
    for disc in &info_disclosure.disclosing_headers {
        all_findings.push(Finding::new(
            "INFO-DISCLOSE",
            &format!("Information disclosure via {}", disc.header),
            disc.severity,
            &format!("{}: {}", disc.disclosure_type, disc.value),
            "Remove or suppress version-disclosing headers.",
        ));
    }

    // Add mixed content findings
    for mc in &mixed_content {
        all_findings.push(Finding::new(
            "MIXED-CONTENT",
            &format!("Mixed content: {} from {}", mc.element_type, mc.url),
            mc.severity,
            &format!("{} content loaded over HTTP on an HTTPS page", mc.element_type),
            "Change all resource URLs to HTTPS.",
        ).with_detail(format!("Element: {}, URL: {}", mc.element_type, mc.url)));
    }

    all_findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    Ok(WebReport {
        final_url,
        status,
        server: headers
            .get("server")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        powered_by: headers
            .get("x-powered-by")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        content_type: headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        security_headers,
        security_header_findings,
        csp_findings,
        robots_txt_present: robots_txt_result.is_some(),
        sitemap_present: sitemap_handle.join().expect("sitemap probe thread panicked"),
        tls,
        tls_config,
        redirects,
        cookies,
        enhanced_cookies,
        cors,
        cors_preflight,
        tech,
        method_probes,
        cache_control,
        mixed_content,
        info_disclosure,
        hsts_preload,
        clickjacking,
        protocol_support,
        robots_review,
        security_txt: security_txt_report,
        sri,
        all_findings,
    })
}

fn is_public_resource_present(client: &Client, url: &Url) -> bool {
    client
        .get(url.as_str())
        .send()
        .map(|response| response.status().is_success())
        .unwrap_or(false)
}

fn fetch_resource_text(client: &Client, url: &Url) -> Option<String> {
    client
        .get(url.as_str())
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.text().ok())
}

fn inspect_tls_info(url: &Url) -> TlsInfo {
    if url.scheme() != "https" {
        return TlsInfo {
            enabled: false,
            subject: None,
            issuer: None,
            expiry: None,
            days_until_expiry: None,
            san: vec![],
        };
    }

    let host = url.host_str().unwrap_or("localhost");
    let port = url.port().unwrap_or(443);

    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .ok()
        .map(|i| i.take(5).collect())
        .unwrap_or_default();

    if addrs.is_empty() {
        return TlsInfo {
            enabled: true,
            subject: None,
            issuer: None,
            expiry: None,
            days_until_expiry: None,
            san: vec![],
        };
    }

    let mut builder = SslConnector::builder(SslMethod::tls_client()).ok();
    if let Some(ref mut b) = builder {
        b.set_verify(SslVerifyMode::NONE);
    }

    let connector = match builder {
        Some(b) => b.build(),
        None => {
            return TlsInfo {
                enabled: true,
                subject: None,
                issuer: None,
                expiry: None,
                days_until_expiry: None,
                san: vec![],
            }
        }
    };

    for addr in &addrs {
        let stream = match TcpStream::connect_timeout(addr, Duration::from_secs(5)) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let ssl_stream = match connector.connect(host, stream) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if let Some(cert) = ssl_stream.ssl().peer_certificate() {
            return parse_x509_cert(&cert);
        }
    }

    TlsInfo {
        enabled: true,
        subject: None,
        issuer: None,
        expiry: None,
        days_until_expiry: None,
        san: vec![],
    }
}

fn parse_x509_cert(cert: &X509) -> TlsInfo {
    let subject = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

    let issuer = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

    let expiry_str = cert
        .not_after()
        .to_string();

    let expiry_dt = DateTime::parse_from_rfc3339(&expiry_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let days_until_expiry = (expiry_dt - Utc::now()).num_days();

    let san = cert
        .subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.dnsname().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    TlsInfo {
        enabled: true,
        subject,
        issuer,
        expiry: Some(expiry_str),
        days_until_expiry: Some(days_until_expiry),
        san,
    }
}

fn extract_redirect_chain(_client: &Client, base_url: &Url) -> Vec<RedirectHop> {
    let mut redirects = Vec::new();
    let mut current_url = base_url.clone();
    let mut prev_url = base_url.to_string();

    // Build a no-redirect client from the existing one's config
    let no_redirect_client = match Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .user_agent("web-security-auditor/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => return redirects,
    };

    for i in 0..10 {
        let response = no_redirect_client.get(current_url.as_str()).send();

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if (300..400).contains(&status) {
                    if let Some(location) = resp.headers().get("location") {
                        if let Ok(location_str) = location.to_str() {
                            let next_url = current_url.join(location_str).unwrap_or_else(|_| {
                                Url::parse(location_str).unwrap_or(current_url.clone())
                            });
                            redirects.push(RedirectHop {
                                index: i,
                                from_url: prev_url.clone(),
                                to_url: next_url.to_string(),
                                status,
                            });
                            prev_url = current_url.to_string();
                            current_url = next_url;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    redirects
}

fn analyze_cookies(headers: &reqwest::header::HeaderMap) -> Vec<CookieCheck> {
    let mut cookies = Vec::new();

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

            let mut secure = false;
            let mut httponly = false;
            let mut samesite = None;

            for part in &parts[1..] {
                let trimmed = part.trim().to_lowercase();
                if trimmed == "secure" {
                    secure = true;
                } else if trimmed == "httponly" {
                    httponly = true;
                } else if trimmed.starts_with("samesite=") {
                    samesite = Some(trimmed.strip_prefix("samesite=").unwrap_or("").to_string());
                }
            }

            cookies.push(CookieCheck {
                name,
                secure,
                httponly,
                samesite,
            });
        }
    }

    cookies
}

fn check_cors_headers(headers: &reqwest::header::HeaderMap) -> CorsCheck {
    let allow_origin = headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let allow_credentials = headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let wildcard_origin = allow_origin
        .as_ref()
        .map(|v| v == "*")
        .unwrap_or(false);

    CorsCheck {
        header_present: allow_origin.is_some(),
        allow_origin,
        allow_credentials,
        wildcard_origin,
    }
}

fn fingerprint_technologies(headers: &reqwest::header::HeaderMap) -> TechFingerprint {
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let powered_by = headers
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let mut detected = Vec::new();

    if let Some(ref server_val) = server {
        let lower = server_val.to_lowercase();
        if lower.contains("nginx") {
            detected.push("Nginx".to_string());
        }
        if lower.contains("apache") {
            detected.push("Apache".to_string());
        }
        if lower.contains("iis") || lower.contains("microsoft") {
            detected.push("IIS".to_string());
        }
        if lower.contains("cloudflare") {
            detected.push("Cloudflare".to_string());
        }
        if lower.contains("gunicorn") {
            detected.push("Gunicorn".to_string());
        }
        if lower.contains("uvicorn") {
            detected.push("Uvicorn".to_string());
        }
    }

    if let Some(ref powered_val) = powered_by {
        let lower = powered_val.to_lowercase();
        if lower.contains("express") {
            detected.push("Express.js".to_string());
        }
        if lower.contains("asp.net") {
            detected.push("ASP.NET".to_string());
        }
        if lower.contains("php") {
            detected.push("PHP".to_string());
        }
        if lower.contains("django") {
            detected.push("Django".to_string());
        }
        if lower.contains("flask") {
            detected.push("Flask".to_string());
        }
        if lower.contains("rails") {
            detected.push("Ruby on Rails".to_string());
        }
    }

    if headers.contains_key("x-aspnet-version") {
        if !detected.iter().any(|t| t == "ASP.NET") {
            detected.push("ASP.NET".to_string());
        }
    }

    if headers.contains_key("x-drupal-cache") || headers.contains_key("x-drupal-dynamic-cache") {
        detected.push("Drupal".to_string());
    }

    if headers.contains_key("x-wordpress-cache") || headers.get("link").and_then(|v| v.to_str().ok()).map(|v| v.contains("wp-json")).unwrap_or(false) {
        detected.push("WordPress".to_string());
    }

    TechFingerprint {
        server,
        powered_by,
        detected_technologies: detected,
    }
}

fn worker_count_for_len(requested: usize, len: usize) -> usize {
    requested.max(1).min(len.max(1))
}

fn resolve_socket_addrs(
    host: &str,
    port: u16,
) -> std::io::Result<impl Iterator<Item = SocketAddr>> {
    (host, port).to_socket_addrs()
}
