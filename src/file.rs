use anyhow::Result;
use reqwest::blocking::Client;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct PathProbe {
    pub path: String,
    pub status: Option<u16>,
    pub interesting: bool,
}

const DEFAULT_PATHS: &[&str] = &[
    "/",
    "/login",
    "/admin",
    "/dashboard",
    "/api",
    "/api/health",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git",
    "/.git/config",
    "/wp-admin",
    "/wp-login.php",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/debug",
    "/console",
    "/swagger-ui.html",
    "/api/docs",
    "/graphql",
];

pub fn probe_common_paths(
    client: &Client,
    base_url: &Url,
    extra_paths: &[String],
    workers: usize,
) -> Result<Vec<PathProbe>> {
    let paths = build_probe_paths(extra_paths);
    let worker_count = worker_count_for_len(workers, paths.len());
    let queue: Arc<Mutex<VecDeque<(usize, String)>>> =
        Arc::new(Mutex::new(paths.into_iter().enumerate().collect()));
    let base_url = Arc::new(base_url.clone());
    let results = Arc::new(Mutex::new(vec![
        None;
        queue
            .lock()
            .expect("path queue lock poisoned")
            .len()
    ]));

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let client = client.clone();
        let queue = Arc::clone(&queue);
        let base_url = Arc::clone(&base_url);
        let results = Arc::clone(&results);

        handles.push(thread::spawn(move || loop {
            let job = {
                let mut queue = queue.lock().expect("path queue lock poisoned");
                queue.pop_front()
            };

            let Some((index, path)) = job else {
                break;
            };

            let status = base_url
                .join(path.trim_start_matches('/'))
                .ok()
                .and_then(|url| client.get(url).send().ok())
                .map(|response| response.status().as_u16());

            let interesting = is_interesting_status(status);
            let mut results = results.lock().expect("path results lock poisoned");
            results[index] = Some(PathProbe {
                path,
                status,
                interesting,
            });
        }));
    }

    for handle in handles {
        handle.join().expect("path probe worker panicked");
    }

    Ok(Arc::try_unwrap(results)
        .expect("path results still referenced")
        .into_inner()
        .expect("path results lock poisoned")
        .into_iter()
        .flatten()
        .collect())
}

pub fn build_probe_paths(extra_paths: &[String]) -> Vec<String> {
    let mut paths: Vec<String> = DEFAULT_PATHS
        .iter()
        .map(|path| (*path).to_string())
        .collect();

    for path in extra_paths {
        let normalized = normalize_path(path);
        if !paths.contains(&normalized) {
            paths.push(normalized);
        }
    }

    paths
}

pub fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

pub fn is_interesting_status(status: Option<u16>) -> bool {
    matches!(
        status,
        Some(200 | 201 | 202 | 204 | 301 | 302 | 307 | 401 | 403)
    )
}

fn worker_count_for_len(requested: usize, len: usize) -> usize {
    requested.max(1).min(len.max(1))
}

#[cfg(test)]
mod tests {
    use super::{build_probe_paths, is_interesting_status, normalize_path};

    #[test]
    fn normalize_path_adds_leading_slash() {
        assert_eq!(normalize_path("admin"), "/admin");
        assert_eq!(normalize_path("/login"), "/login");
    }

    #[test]
    fn build_probe_paths_deduplicates_custom_entries() {
        let extra = vec![
            "admin".to_string(),
            "/admin".to_string(),
            "health".to_string(),
        ];
        let paths = build_probe_paths(&extra);

        assert_eq!(
            paths
                .iter()
                .filter(|path| path.as_str() == "/admin")
                .count(),
            1
        );
        assert!(paths.contains(&"/health".to_string()));
    }

    #[test]
    fn interesting_status_matches_expected_codes() {
        assert!(is_interesting_status(Some(200)));
        assert!(is_interesting_status(Some(403)));
        assert!(!is_interesting_status(Some(404)));
        assert!(!is_interesting_status(None));
    }
}
