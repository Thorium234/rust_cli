use anyhow::Result;
use reqwest::blocking::Client;
use url::Url;

#[derive(Debug, Clone)]
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
];

pub fn probe_common_paths(
    client: &Client,
    base_url: &Url,
    extra_paths: &[String],
) -> Result<Vec<PathProbe>> {
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

    let mut probes = Vec::with_capacity(paths.len());
    for path in paths {
        let status = base_url
            .join(path.trim_start_matches('/'))
            .ok()
            .and_then(|url| client.get(url).send().ok())
            .map(|response| response.status().as_u16());

        let interesting = matches!(
            status,
            Some(200 | 201 | 202 | 204 | 301 | 302 | 307 | 401 | 403)
        );
        probes.push(PathProbe {
            path,
            status,
            interesting,
        });
    }

    Ok(probes)
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}
