pub(crate) const APP_USER_AGENT: &str = "Domain Shepherd/0.1.0";
pub(crate) const WHOIS_TIMEOUT_MS: u64 = 7000;
pub(crate) const REQUEST_TIMEOUT_MS: u64 = 12_000;
pub(crate) const MAX_REDIRECTS: usize = 8;
pub(crate) const DEFAULT_BATCH_CONCURRENCY: usize = 10;
pub(crate) const MIN_BATCH_CONCURRENCY: usize = 1;
pub(crate) const MAX_BATCH_CONCURRENCY: usize = 50;
pub(crate) const WHOIS_PRIMARY_SERVER: &str = "whois.iana.org";

pub(crate) fn normalize_batch_concurrency(value: Option<usize>) -> usize {
    match value {
        Some(v) if v < MIN_BATCH_CONCURRENCY => MIN_BATCH_CONCURRENCY,
        Some(v) if v > MAX_BATCH_CONCURRENCY => MAX_BATCH_CONCURRENCY,
        Some(v) => v,
        None => DEFAULT_BATCH_CONCURRENCY,
    }
}

pub(crate) const PARKING_SIGNALS: [&str; 6] = [
    "sedoparking",
    "parkingcrew",
    "bodis",
    "afternic",
    "dan.com",
    "undeveloped",
];

#[derive(Debug)]
pub(crate) struct DnsType;

impl DnsType {
    pub(crate) const A: u32 = 1;
    pub(crate) const NS: u32 = 2;
    pub(crate) const CNAME: u32 = 5;
    pub(crate) const AAAA: u32 = 28;
}

#[derive(Debug)]
pub(crate) struct WhoisOverrides;

impl WhoisOverrides {
    pub(crate) fn get(tld: &str) -> Option<&'static str> {
        match tld {
            "ai" => Some("whois.nic.ai"),
            "de" => Some("whois.denic.de"),
            "io" => Some("whois.nic.io"),
            "org" => Some("whois.pir.org"),
            "uk" => Some("whois.nominet.uk"),
            "fr" => Some("whois.afnic.fr"),
            _ => None,
        }
    }
}
