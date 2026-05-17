use reqwest::header::ACCEPT;

use super::constants::DnsType;
use super::types::{DnsLookupResult, DnsLookupValues, DnsResponse};
use super::util::dedupe_strings_sorted;

pub(crate) async fn resolve_dns(domain: &str) -> Result<DnsLookupResult, String> {
    let (a, aaaa, cname, ns) = futures::join!(
        resolve_doh(domain, DnsType::A),
        resolve_doh(domain, DnsType::AAAA),
        resolve_doh(domain, DnsType::CNAME),
        resolve_doh(domain, DnsType::NS)
    );

    let addresses = dedupe_strings_sorted([
        a.as_ref().ok().map(|r| r.values.clone()).unwrap_or_default(),
        aaaa.as_ref().ok().map(|r| r.values.clone()).unwrap_or_default(),
    ]
    .concat());

    let cname_values = cname.as_ref().ok().map(|r| r.values.clone()).unwrap_or_default();
    let name_servers = ns
        .as_ref()
        .ok()
        .map(|r| dedupe_strings_sorted(r.values.clone()))
        .unwrap_or_default();

    if !addresses.is_empty() || !cname_values.is_empty() {
        return Ok(DnsLookupResult {
            addresses,
            cname: cname_values.first().cloned(),
            name_servers,
            dns_error: None,
        });
    }

    let errors = [a.as_ref().err(), aaaa.as_ref().err(), cname.as_ref().err()]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    let statuses = [a.as_ref().ok(), aaaa.as_ref().ok(), cname.as_ref().ok()]
        .into_iter()
        .flatten()
        .filter_map(|result| result.status)
        .filter(|status| *status != 0)
        .collect::<Vec<_>>();

    Ok(DnsLookupResult {
        addresses,
        cname: cname_values.first().cloned(),
        name_servers,
        dns_error: errors
            .first()
            .cloned()
            .or_else(|| statuses.first().map(|status| format!("DNS response status {status}")))
            .or_else(|| Some("No DNS records found".to_string())),
    })
}

async fn resolve_doh(domain: &str, record_type: u32) -> Result<DnsLookupValues, String> {
    let client = super::http::build_http_client()?;
    let response = client
        .get(format!(
            "https://dns.google/resolve?name={}&type={record_type}",
            urlencoding::encode(domain)
        ))
        .header(ACCEPT, "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("DNS lookup failed with status {}", response.status()));
    }

    let payload = response
        .json::<DnsResponse>()
        .await
        .map_err(|e| format!("DNS payload decode failed: {e}"))?;

    let values = payload
        .answer
        .unwrap_or_default()
        .into_iter()
        .filter(|answer| answer.type_id == Some(record_type))
        .filter_map(|answer| answer.data)
        .map(|data| data.trim_end_matches('.').to_string())
        .collect::<Vec<_>>();

    Ok(DnsLookupValues {
        values,
        status: payload.status,
    })
}
