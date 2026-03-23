use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::thread;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct RateLimitObservation {
    pub attempt: usize,
    pub status: Option<u16>,
    pub retry_after: Option<String>,
    pub remaining: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RateLimitReport {
    pub observations: Vec<RateLimitObservation>,
    pub limit_detected: bool,
}

pub fn probe_rate_limiting(client: &Client, url: &Url, requests: usize) -> Result<RateLimitReport> {
    let total = requests.max(1);
    let mut observations = Vec::with_capacity(total);

    for attempt in 1..=total {
        let response = client
            .get(url.as_str())
            .send()
            .with_context(|| format!("rate-limit probe failed on attempt {attempt}"))?;

        let headers = response.headers().clone();
        let status = response.status().as_u16();
        let retry_after = headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);

        observations.push(RateLimitObservation {
            attempt,
            status: Some(status),
            retry_after,
            remaining,
        });

        thread::sleep(Duration::from_millis(150));
    }

    let limit_detected = observations.iter().any(|item| {
        matches!(item.status, Some(429)) || item.retry_after.is_some() || item.remaining.is_some()
    });

    Ok(RateLimitReport {
        observations,
        limit_detected,
    })
}
