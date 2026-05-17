use std::collections::HashSet;

use regex::RegexBuilder;

use super::constants::PARKING_SIGNALS;
use super::types::{ParkedPattern, ProbeStatus};
use url::Url;

pub(crate) fn normalize_domain(domain: &str) -> String {
    let trimmed = domain.trim().to_lowercase();
    if trimmed.is_empty() {
        return trimmed;
    }

    let parsed = Url::parse(&trimmed)
        .ok()
        .or_else(|| Url::parse(&format!("http://{trimmed}")).ok());

    let base = parsed
        .and_then(|url| url.host_str().map(|host| host.to_lowercase()))
        .unwrap_or_else(|| {
            trimmed
                .rsplit('@')
                .next()
                .unwrap_or(&trimmed)
                .split(|c| c == '/' || c == '?' || c == '#')
                .next()
                .unwrap_or("")
                .to_string()
        });

    base.trim_end_matches('.').to_string()
}

pub(crate) fn extract_frameset_url(final_url: Option<&str>, body_text: &str) -> Option<String> {
    let final_url = final_url?;
    let lower_body = body_text.to_lowercase();
    if !lower_body.contains("<frameset") {
        return None;
    }

    let frame_tag_regex = RegexBuilder::new(r"<frame\b[^>]*>")
        .case_insensitive(true)
        .build()
        .ok()?;
    let frame_tag = frame_tag_regex.find(body_text).map(|m| m.as_str())?;

    let src_regex = RegexBuilder::new(r#"\bsrc\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))"#)
        .case_insensitive(true)
        .build()
        .ok()?;
    let captures = src_regex.captures(frame_tag)?;
    let src = captures
        .get(1)
        .or_else(|| captures.get(2))
        .or_else(|| captures.get(3))
        .map(|m| m.as_str())
        .unwrap_or("")
        .trim();

    if src.is_empty() {
        return None;
    }

    Url::parse(final_url)
        .ok()
        .and_then(|base| base.join(src).ok())
        .map(|url| url.to_string())
}

pub(crate) fn classify_probe_status(
    domain: &str,
    final_url: Option<&str>,
    redirect_chain: &[String],
    server_header: Option<&str>,
    content_type: Option<&str>,
) -> ProbeStatus {
    let Some(final_url) = final_url else {
        return ProbeStatus::Unreachable;
    };

    if !redirect_chain.is_empty() {
        return ProbeStatus::Redirected;
    }

    let parked_signals = [Some(final_url), server_header, content_type]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    if PARKING_SIGNALS
        .iter()
        .any(|signal| parked_signals.contains(signal))
    {
        return ProbeStatus::Parked;
    }

    let final_host = match Url::parse(final_url)
        .ok()
        .and_then(|url| url.host_str().map(|h| h.to_lowercase()))
    {
        Some(host) => host,
        None => return ProbeStatus::Unreachable,
    };

    if final_host != domain && final_host != format!("www.{domain}") {
        return ProbeStatus::Redirected;
    }

    ProbeStatus::Ok
}

fn get_name_server_sld(name_server: &str) -> String {
    let parts = name_server
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if parts.len() < 2 {
        return String::new();
    }

    format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]).to_lowercase()
}

fn get_name_server_sld_label(name_server_sld: &str) -> String {
    name_server_sld
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

pub(crate) fn matches_configured_parked_patterns(
    patterns: &[ParkedPattern],
    dns_name_servers: &[String],
    response_body: &str,
) -> bool {
    if patterns.is_empty() || response_body.is_empty() {
        return false;
    }

    let mut ns_slds = HashSet::new();
    for name_server in dns_name_servers {
        let full_sld = get_name_server_sld(name_server);
        if full_sld.is_empty() {
            continue;
        }

        ns_slds.insert(full_sld.clone());
        let label = get_name_server_sld_label(&full_sld);
        if !label.is_empty() {
            ns_slds.insert(label);
        }
    }

    for pattern in patterns {
        if let Some(ns_sld) = &pattern.ns_sld {
            let normalized = ns_sld.trim().to_lowercase().trim_end_matches('.').to_string();
            if normalized.is_empty() || !ns_slds.contains(&normalized) {
                continue;
            }
        }

        let regex = RegexBuilder::new(pattern.response_regex.trim())
            .case_insensitive(true)
            .build();

        if let Ok(regex) = regex {
            if regex.is_match(response_body) {
                return true;
            }
        }
    }

    false
}

pub(crate) fn dedupe_insertion_order(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }

    deduped
}

pub(crate) fn dedupe_strings_sorted(values: Vec<String>) -> Vec<String> {
    let mut deduped = values
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    deduped.sort();
    deduped
}

pub(crate) fn clean_whois_response(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\0', "").trim().to_string()
}

pub(crate) fn split_whois_label(line: &str) -> Option<(String, String)> {
    let (left, right) = line.split_once(':')?;
    Some((left.trim().to_string(), right.trim().to_string()))
}

pub(crate) fn find_whois_field(text: &str, labels: &[&str]) -> Option<String> {
    for line in text.lines() {
        if let Some((key, value)) = split_whois_label(line) {
            for label in labels {
                if key.eq_ignore_ascii_case(label) && !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

pub(crate) fn find_whois_fields(text: &str, labels: &[&str]) -> Vec<String> {
    let mut values = Vec::new();

    for line in text.lines() {
        if let Some((key, value)) = split_whois_label(line) {
            if value.is_empty() {
                continue;
            }
            if labels.iter().any(|label| key.eq_ignore_ascii_case(label)) {
                values.push(value);
            }
        }
    }

    dedupe_insertion_order(values)
}

pub(crate) fn first_whois_value(text: &str, labels: &[&str]) -> Option<String> {
    find_whois_field(text, labels).or_else(|| find_whois_fields(text, labels).into_iter().next())
}

pub(crate) fn normalize_whois_statuses(values: Vec<String>) -> Vec<String> {
    let mapped = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| {
            if let Some((left, _)) = value.split_once(" http") {
                left.trim().to_string()
            } else {
                value
            }
        })
        .map(|value| value.split_whitespace().next().unwrap_or("").to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    dedupe_insertion_order(mapped)
}

pub(crate) fn normalize_whois_name_server(value: &str) -> Option<String> {
    let candidate = value
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_lowercase();

    if candidate.is_empty() || !candidate.contains('.') {
        return None;
    }

    if candidate
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'))
    {
        return None;
    }

    Some(candidate)
}

pub(crate) fn find_whois_name_servers(text: &str) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    let mut in_name_server_block = false;

    for raw_line in text.lines() {
        let line = raw_line.replace('\r', "");
        let trimmed = line.trim();

        if trimmed.is_empty() {
            in_name_server_block = false;
            continue;
        }

        if let Some((key, value)) = split_whois_label(trimmed) {
            let is_ns_label = ["Name Server", "Nameserver", "Name Servers", "nserver"]
                .iter()
                .any(|label| key.eq_ignore_ascii_case(label));

            if is_ns_label {
                if let Some(normalized) = normalize_whois_name_server(&value) {
                    values.push(normalized);
                }
                in_name_server_block = key.eq_ignore_ascii_case("Name Servers") && value.is_empty();
                continue;
            }

            if in_name_server_block {
                in_name_server_block = false;
            }
        }

        if in_name_server_block {
            if let Some(normalized) = normalize_whois_name_server(trimmed) {
                values.push(normalized);
                continue;
            }
            in_name_server_block = false;
        }
    }

    dedupe_insertion_order(values)
}

#[cfg(test)]
mod tests {
    use super::extract_frameset_url;

    #[test]
    fn extracts_frame_src_relative_to_final_url() {
        let html = r#"<html><frameset rows=\"100%\"><frame src=\"/schufa-frei/\" /></frameset></html>"#;
        let result = extract_frameset_url(Some("https://www.schufa.de/root/path"), html);
        assert_eq!(result.as_deref(), Some("https://www.schufa.de/schufa-frei/"));
    }

    #[test]
    fn does_not_treat_frameset_tag_as_frame_tag() {
        let html = r#"<html><frameset cols=\"100%\"><frame src=\"https://target.example/\"></frameset></html>"#;
        let result = extract_frameset_url(Some("https://origin.example/"), html);
        assert_eq!(result.as_deref(), Some("https://target.example/"));
    }

    #[test]
    fn extracts_uppercase_frame_src_case_insensitive() {
        let html = r#"<HTML><FRAMESET ROWS="100%"><FRAME SRC="/upper"></FRAMESET></HTML>"#;
        let result = extract_frameset_url(Some("https://example.org/base"), html);
        assert_eq!(result.as_deref(), Some("https://example.org/upper"));
    }
}
