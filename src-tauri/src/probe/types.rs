use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeDomainInput {
    pub id: String,
    pub domain: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParkedPattern {
    #[serde(default)]
    pub ns_sld: Option<String>,
    pub response_regex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeStatus {
    Ok,
    Redirected,
    Parked,
    Frameset,
    Unreachable,
    NoDns,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WhoisResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) abuse_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name_servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) statuses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectChainEntry {
    pub(crate) url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) server_header: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub(crate) domain_id: String,
    pub(crate) domain: String,
    pub(crate) status: ProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) redirect_chain: Option<Vec<RedirectChainEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) frameset_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) frameset_http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) server_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dns_name_servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) whois: Option<WhoisResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dns_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_kind: Option<String>,
    pub(crate) dns_ms: u64,
    pub(crate) http_ms: u64,
    pub(crate) whois_ms: u64,
    pub(crate) probe_ms: u64,
}

#[derive(Debug)]
pub(crate) struct DnsLookupResult {
    pub(crate) addresses: Vec<String>,
    pub(crate) cname: Option<String>,
    pub(crate) name_servers: Vec<String>,
    pub(crate) dns_error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct HttpProbeResult {
    pub(crate) status: ProbeStatus,
    pub(crate) http_status: Option<u16>,
    pub(crate) redirect_chain: Vec<RedirectChainEntry>,
    pub(crate) final_url: Option<String>,
    pub(crate) frameset_url: Option<String>,
    pub(crate) frameset_http_status: Option<u16>,
    pub(crate) server_header: Option<String>,
    pub(crate) content_type: Option<String>,
    pub(crate) timed_out: bool,
    pub(crate) error: Option<String>,
    pub(crate) error_kind: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct DnsAnswer {
    #[serde(rename = "data")]
    pub(crate) data: Option<String>,
    #[serde(rename = "type")]
    pub(crate) type_id: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct DnsResponse {
    #[serde(rename = "Status")]
    pub(crate) status: Option<u32>,
    #[serde(rename = "Answer")]
    pub(crate) answer: Option<Vec<DnsAnswer>>,
}

#[derive(Debug)]
pub(crate) struct DnsLookupValues {
    pub(crate) values: Vec<String>,
    pub(crate) status: Option<u32>,
}
