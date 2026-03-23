use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use std::fmt;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;
use url::Url;

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
    pub robots_txt_present: bool,
    pub sitemap_present: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderCheck {
    pub name: &'static str,
    pub present: bool,
    pub value: Option<String>,
}

pub fn scan_ports(host: &str, ports: &[u16], timeout: Duration) -> Vec<PortResult> {
    let mut handles = Vec::with_capacity(ports.len());

    for (index, port) in ports.iter().copied().enumerate() {
        let host = host.to_string();
        handles.push(thread::spawn(move || {
            let state = resolve_socket_addrs(&host, port)
                .map(|mut addrs| {
                    addrs
                        .find(|addr| TcpStream::connect_timeout(addr, timeout).is_ok())
                        .map(|_| PortState::Open)
                        .unwrap_or(PortState::Closed)
                })
                .unwrap_or(PortState::Unresolved);

            (index, PortResult { port, state })
        }));
    }

    let mut ordered = vec![None; ports.len()];
    for handle in handles {
        let (index, result) = handle.join().expect("port scan thread panicked");
        ordered[index] = Some(result);
    }

    ordered.into_iter().flatten().collect()
}

pub fn web_probe(client: &Client, base_url: &Url) -> Result<WebReport> {
    let response = client
        .get(base_url.as_str())
        .send()
        .with_context(|| format!("request failed for {}", base_url))?;

    let final_url = response.url().to_string();
    let status = response.status().as_u16();
    let headers = response.headers().clone();

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
    let robots_client = client.clone();
    let sitemap_client = client.clone();

    let robots_handle = thread::spawn(move || match robots_url {
        Some(url) => is_public_resource_present(&robots_client, &url),
        None => false,
    });
    let sitemap_handle = thread::spawn(move || match sitemap_url {
        Some(url) => is_public_resource_present(&sitemap_client, &url),
        None => false,
    });

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
        robots_txt_present: robots_handle.join().expect("robots probe thread panicked"),
        sitemap_present: sitemap_handle
            .join()
            .expect("sitemap probe thread panicked"),
    })
}

fn is_public_resource_present(client: &Client, url: &Url) -> bool {
    client
        .get(url.as_str())
        .send()
        .map(|response| response.status().is_success())
        .unwrap_or(false)
}

fn resolve_socket_addrs(
    host: &str,
    port: u16,
) -> std::io::Result<impl Iterator<Item = SocketAddr>> {
    (host, port).to_socket_addrs()
}
