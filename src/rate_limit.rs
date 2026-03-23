use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use serde::Serialize;
use std::thread;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitObservation {
    pub attempt: usize,
    pub status: Option<u16>,
    pub retry_after: Option<String>,
    pub remaining: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
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

        let observation =
            build_observation(attempt, response.status().as_u16(), response.headers());
        observations.push(observation);

        thread::sleep(Duration::from_millis(150));
    }

    Ok(RateLimitReport {
        limit_detected: detect_rate_limiting(&observations),
        observations,
    })
}

pub fn build_observation(attempt: usize, status: u16, headers: &HeaderMap) -> RateLimitObservation {
    let retry_after = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let remaining = headers
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    RateLimitObservation {
        attempt,
        status: Some(status),
        retry_after,
        remaining,
    }
}

pub fn detect_rate_limiting(observations: &[RateLimitObservation]) -> bool {
    observations.iter().any(|item| {
        matches!(item.status, Some(429)) || item.retry_after.is_some() || item.remaining.is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::{build_observation, detect_rate_limiting, RateLimitObservation};
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn detect_rate_limiting_flags_headers_and_429() {
        let observations = vec![
            RateLimitObservation {
                attempt: 1,
                status: Some(200),
                retry_after: None,
                remaining: None,
            },
            RateLimitObservation {
                attempt: 2,
                status: Some(429),
                retry_after: Some("10".to_string()),
                remaining: Some("0".to_string()),
            },
        ];

        assert!(detect_rate_limiting(&observations));
    }

    #[test]
    fn detect_rate_limiting_ignores_normal_traffic() {
        let observations = vec![
            RateLimitObservation {
                attempt: 1,
                status: Some(200),
                retry_after: None,
                remaining: None,
            },
            RateLimitObservation {
                attempt: 2,
                status: Some(204),
                retry_after: None,
                remaining: None,
            },
        ];

        assert!(!detect_rate_limiting(&observations));
    }

    #[test]
    fn build_observation_extracts_rate_limit_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("30"));
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));

        let observation = build_observation(3, 429, &headers);

        assert_eq!(observation.attempt, 3);
        assert_eq!(observation.status, Some(429));
        assert_eq!(observation.retry_after.as_deref(), Some("30"));
        assert_eq!(observation.remaining.as_deref(), Some("0"));
    }
}
