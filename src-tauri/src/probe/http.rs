use reqwest::header::{ACCEPT, LOCATION, SERVER, USER_AGENT};
use reqwest::Client;

use super::constants::{APP_USER_AGENT, MAX_REDIRECTS, REQUEST_TIMEOUT_MS};
use super::types::HttpProbeResult;
use super::util::{classify_probe_status, extract_frameset_url, matches_configured_parked_patterns};

async fn follow_url_redirects(client: &Client, initial_url: &str) -> (String, Option<u16>) {
    let mut current_url = initial_url.to_string();

    for _ in 0..=MAX_REDIRECTS {
        let response = client
            .get(&current_url)
            .header(ACCEPT, "text/html,*/*")
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(_) => return (current_url, None),
        };

        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        if status.is_redirection() {
            if let Some(location) = location {
                let next_url = url::Url::parse(&current_url)
                    .ok()
                    .and_then(|url| url.join(&location).ok())
                    .map(|url| url.to_string())
                    .unwrap_or(location);

                current_url = next_url;
                continue;
            }
        }

        return (current_url, Some(status.as_u16()));
    }

    (current_url, None)
}

pub(crate) fn build_http_client() -> Result<Client, String> {
    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(USER_AGENT, reqwest::header::HeaderValue::from_static(APP_USER_AGENT));

    Client::builder()
        .timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS))
        .default_headers(default_headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client build failed: {e}"))
}

pub(crate) async fn follow_http(
    domain: &str,
    dns_name_servers: &[String],
    parked_patterns: &[super::types::ParkedPattern],
) -> HttpProbeResult {
    let client = match build_http_client() {
        Ok(client) => client,
        Err(error) => {
            return HttpProbeResult {
                status: super::types::ProbeStatus::Unreachable,
                http_status: None,
                redirect_chain: Vec::new(),
                final_url: None,
                frameset_url: None,
                frameset_http_status: None,
                server_header: None,
                content_type: None,
                timed_out: false,
                error: Some(error),
                error_kind: Some("network-error".to_string()),
            }
        }
    };

    let mut redirect_chain: Vec<String> = Vec::new();
    let mut current_url = format!("https://{domain}");
    let mut allow_http_fallback = true;

    for _ in 0..=MAX_REDIRECTS {
        let response = client
            .get(&current_url)
            .header(ACCEPT, "text/html,*/*")
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                if allow_http_fallback && current_url.starts_with("https://") {
                    current_url = format!("http://{domain}");
                    allow_http_fallback = false;
                    continue;
                }

                return HttpProbeResult {
                    status: if error.is_timeout() {
                        super::types::ProbeStatus::Timeout
                    } else {
                        super::types::ProbeStatus::Unreachable
                    },
                    http_status: None,
                    redirect_chain,
                    final_url: Some(current_url),
                    frameset_url: None,
                    frameset_http_status: None,
                    server_header: None,
                    content_type: None,
                    timed_out: error.is_timeout(),
                    error: Some(error.to_string()),
                    error_kind: Some(if error.is_timeout() {
                        "request-timeout".to_string()
                    } else {
                        "network-error".to_string()
                    }),
                };
            }
        };

        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        if status.is_redirection() {
            if let Some(location) = location {
                let next_url = url::Url::parse(&current_url)
                    .ok()
                    .and_then(|url| url.join(&location).ok())
                    .map(|url| url.to_string())
                    .unwrap_or(location);

                redirect_chain.push(current_url.clone());
                current_url = next_url;
                allow_http_fallback = false;
                continue;
            }
        }

        let final_url = Some(current_url.clone());
        let server_header = response
            .headers()
            .get(SERVER)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let body_text = response.text().await.unwrap_or_default();
        let frameset_source_url = extract_frameset_url(final_url.as_deref(), &body_text);
        let configured_parked =
            matches_configured_parked_patterns(parked_patterns, dns_name_servers, &body_text);
        let (frameset_url, frameset_http_status) = if let Some(source) = frameset_source_url {
            let (resolved_url, resolved_status) = follow_url_redirects(&client, &source).await;
            (Some(resolved_url), resolved_status)
        } else {
            (None, None)
        };

        return HttpProbeResult {
            status: if configured_parked {
                super::types::ProbeStatus::Parked
            } else if frameset_url.is_some() {
                super::types::ProbeStatus::Frameset
            } else {
                classify_probe_status(
                    domain,
                    final_url.as_deref(),
                    &redirect_chain,
                    server_header.as_deref(),
                    content_type.as_deref(),
                )
            },
            http_status: Some(status.as_u16()),
            redirect_chain,
            final_url,
            frameset_url,
            frameset_http_status,
            server_header,
            content_type,
            timed_out: false,
            error: if status.is_success() {
                None
            } else {
                Some(format!("HTTP request returned {}", status.as_u16()))
            },
            error_kind: if status.is_success() {
                None
            } else {
                Some("network-error".to_string())
            },
        };
    }

    HttpProbeResult {
        status: super::types::ProbeStatus::Unreachable,
        http_status: None,
        redirect_chain,
        final_url: Some(current_url),
        frameset_url: None,
        frameset_http_status: None,
        server_header: None,
        content_type: None,
        timed_out: false,
        error: Some(format!("Exceeded {MAX_REDIRECTS} redirects")),
        error_kind: Some("redirect-limit".to_string()),
    }
}
