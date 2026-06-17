mod constants;
mod dns;
mod http;
mod types;
mod util;
mod whois;

use std::sync::Arc;
use std::time::Instant;

use futures::future::join_all;
use tokio::sync::Semaphore;

pub use types::{ProbeDomainInput, ProbeResult, ProbeStatus, WhoisResult};

use constants::normalize_batch_concurrency;
use dns::resolve_dns;
use http::follow_http;
use util::normalize_domain;
use whois::fetch_whois;

#[tauri::command]
pub async fn run_probe_batch(
    domains: Vec<ProbeDomainInput>,
    concurrency: Option<usize>,
    parked_patterns: Option<Vec<types::ParkedPattern>>,
) -> Result<Vec<ProbeResult>, String> {
    run_probe_batch_internal(domains, concurrency, parked_patterns).await
}

pub async fn run_probe_batch_internal(
    domains: Vec<ProbeDomainInput>,
    concurrency: Option<usize>,
    parked_patterns: Option<Vec<types::ParkedPattern>>,
) -> Result<Vec<ProbeResult>, String> {
    let semaphore = Arc::new(Semaphore::new(normalize_batch_concurrency(concurrency)));
    let parked_patterns = Arc::new(parked_patterns.unwrap_or_default());
    let mut tasks = Vec::with_capacity(domains.len());

    for (index, domain) in domains.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        let parked_patterns = parked_patterns.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.map_err(|e| e.to_string())?;
            let result = probe_domain(domain, parked_patterns.as_slice()).await;
            Ok::<(usize, ProbeResult), String>((index, result))
        }));
    }

    let mut ordered = vec![None; tasks.len()];
    for joined in join_all(tasks).await {
        let (index, result) = joined
            .map_err(|e| format!("Probe task join error: {e}"))?
            .map_err(|e| format!("Probe task error: {e}"))?;
        ordered[index] = Some(result);
    }

    Ok(ordered.into_iter().flatten().collect())
}

#[tauri::command]
pub async fn run_probe_whois(domain: String) -> Result<types::WhoisLookupResult, String> {
    Ok(run_probe_whois_internal(domain).await)
}

pub async fn run_probe_whois_internal(domain: String) -> types::WhoisLookupResult {
    let normalized_domain = normalize_domain(&domain);
    let started = Instant::now();

    if normalized_domain.is_empty() {
        return types::WhoisLookupResult {
            domain: normalized_domain,
            whois: WhoisResult {
                error: Some("Invalid domain".to_string()),
                ..WhoisResult::default()
            },
            whois_ms: 0,
        };
    }

    let whois = fetch_whois(normalized_domain.clone()).await;
    types::WhoisLookupResult {
        domain: normalized_domain,
        whois,
        whois_ms: started.elapsed().as_millis() as u64,
    }
}

async fn probe_domain(domain_input: ProbeDomainInput, parked_patterns: &[types::ParkedPattern]) -> ProbeResult {
    use types::ProbeStatus;

    let started = Instant::now();
    let domain = normalize_domain(&domain_input.domain);

    let mut result = ProbeResult {
        domain_id: domain_input.id,
        domain,
        status: ProbeStatus::Unreachable,
        http_status: None,
        redirect_chain: None,
        final_url: None,
        frameset_url: None,
        frameset_http_status: None,
        server_header: None,
        content_type: None,
        ip_addresses: Some(Vec::new()),
        cname: None,
        dns_name_servers: Some(Vec::new()),
        whois: None,
        dns_error: None,
        error: None,
        error_kind: None,
        dns_ms: 0,
        http_ms: 0,
        whois_ms: 0,
        probe_ms: 0,
    };

    let dns_started = Instant::now();
    match resolve_dns(&result.domain).await {
        Ok(dns) => {
            result.dns_ms = dns_started.elapsed().as_millis() as u64;
            if !dns.addresses.is_empty() {
                result.ip_addresses = Some(dns.addresses.clone());
            }
            result.cname = dns.cname.clone();
            if !dns.name_servers.is_empty() {
                result.dns_name_servers = Some(dns.name_servers.clone());
            }

            if dns.addresses.is_empty() && dns.cname.is_none() {
                result.status = ProbeStatus::NoDns;
                result.dns_error = dns.dns_error;
                result.probe_ms = started.elapsed().as_millis() as u64;
                return result;
            }

            let dns_name_servers = dns.name_servers.clone();
            let http_started = Instant::now();
            let http = follow_http(&result.domain, &dns_name_servers, parked_patterns).await;
            result.http_ms = http_started.elapsed().as_millis() as u64;
            result.status = if http.timed_out { ProbeStatus::Timeout } else { http.status };
            result.http_status = http.http_status;
            if !http.redirect_chain.is_empty() {
                result.redirect_chain = Some(http.redirect_chain);
            }
            result.final_url = http.final_url;
            result.frameset_url = http.frameset_url;
            result.frameset_http_status = http.frameset_http_status;
            result.server_header = http.server_header;
            result.content_type = http.content_type;
            result.error = http.error;
            result.error_kind = http.error_kind;
        }
        Err(error) => {
            result.dns_ms = dns_started.elapsed().as_millis() as u64;
            result.status = ProbeStatus::Unreachable;
            result.error = Some(error);
            result.error_kind = Some("probe-failed".to_string());
        }
    }

    result.probe_ms = started.elapsed().as_millis() as u64;
    result
}
