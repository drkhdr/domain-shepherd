use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::constants::{WHOIS_PRIMARY_SERVER, WHOIS_TIMEOUT_MS, WhoisOverrides};
use super::http::build_http_client;
use super::types::WhoisResult;
use super::util::{
    clean_whois_response, dedupe_strings_sorted, find_whois_field, find_whois_fields, find_whois_name_servers,
    first_whois_value, normalize_whois_statuses,
};

pub(crate) async fn fetch_whois(domain: String) -> WhoisResult {
    let whois = fetch_whois_traditional(&domain).await;
    if whois.error.is_none() {
        return whois;
    }

    let mut rdap = fetch_rdap(&domain).await;
    rdap.raw_text = None;
    rdap
}

async fn fetch_whois_traditional(domain: &str) -> WhoisResult {
    let primary_server = match find_whois_server(domain).await {
        Ok(Some(server)) => server,
        Ok(None) => {
            return WhoisResult {
                error: Some("WHOIS server not found".to_string()),
                ..WhoisResult::default()
            }
        }
        Err(error) => {
            return WhoisResult {
                error: Some(error),
                ..WhoisResult::default()
            }
        }
    };

    let primary_response = match query_whois_server(&primary_server, &get_whois_query(domain, &primary_server)).await {
        Ok(response) => clean_whois_response(&response),
        Err(error) => {
            return WhoisResult {
                error: Some(error),
                ..WhoisResult::default()
            }
        }
    };

    let registrar_whois_server = first_whois_value(
        &primary_response,
        &["Registrar WHOIS Server", "Whois Server", "ReferralServer"],
    )
    .map(|value| value.replacen("whois://", "", 1).trim().to_string())
    .filter(|value| !value.contains('/'));

    let should_follow_referral = registrar_whois_server
        .as_ref()
        .map(|server| server.to_lowercase() != primary_server.to_lowercase())
        .unwrap_or(false);

    let final_server = if should_follow_referral {
        registrar_whois_server.clone().unwrap_or_else(|| primary_server.clone())
    } else {
        primary_server.clone()
    };

    let final_response = if should_follow_referral {
        match query_whois_server(&final_server, &get_whois_query(domain, &final_server)).await {
            Ok(response) => clean_whois_response(&response),
            Err(error) => {
                return WhoisResult {
                    error: Some(error),
                    ..WhoisResult::default()
                }
            }
        }
    } else {
        primary_response.clone()
    };

    let combined = if should_follow_referral {
        format!("{primary_response}\n\n# Registrar WHOIS\n{final_response}")
    } else {
        final_response
    };

    let statuses = normalize_whois_statuses(find_whois_fields(
        &combined,
        &["Domain Status", "Status", "state", "State", "Domain status"],
    ));

    WhoisResult {
        registrar: first_whois_value(
            &combined,
            &[
                "Registrar",
                "registrar",
                "Sponsoring Registrar",
                "Registrar Name",
                "Record maintained by",
            ],
        ),
        created_at: first_whois_value(
            &combined,
            &[
                "Creation Date",
                "Created On",
                "Registered On",
                "Registration Time",
                "Created",
                "Domain Registration Date",
            ],
        ),
        updated_at: first_whois_value(
            &combined,
            &[
                "Updated Date",
                "Last Updated On",
                "Changed",
                "Modified",
                "Last Modified",
                "Changed Date",
            ],
        ),
        expires_at: first_whois_value(
            &combined,
            &[
                "Registry Expiry Date",
                "Registrar Registration Expiration Date",
                "Expiration Date",
                "Expire Date",
                "Paid-till",
                "Expiry Date",
                "Expires On",
                "Renewal Date",
            ],
        ),
        abuse_email: first_whois_value(
            &combined,
            &[
                "Registrar Abuse Contact Email",
                "abuse-mailbox",
                "OrgAbuseEmail",
                "Abuse Contact Email",
            ],
        ),
        server: Some(final_server),
        name_servers: {
            let ns = find_whois_name_servers(&combined);
            if ns.is_empty() { None } else { Some(ns) }
        },
        statuses: if statuses.is_empty() { None } else { Some(statuses) },
        raw_text: if combined.is_empty() { None } else { Some(combined) },
        error: None,
    }
}

async fn find_whois_server(domain: &str) -> Result<Option<String>, String> {
    let tld = domain
        .split('.')
        .next_back()
        .map(|t| t.to_lowercase())
        .ok_or_else(|| "Invalid domain".to_string())?;

    if let Some(override_server) = WhoisOverrides::get(&tld) {
        return Ok(Some(override_server.to_string()));
    }

    let iana_response = query_whois_server(WHOIS_PRIMARY_SERVER, &tld).await?;
    Ok(find_whois_field(&iana_response, &["refer", "whois"]))
}

fn get_whois_query(domain: &str, server: &str) -> String {
    if server == "whois.denic.de" {
        return format!("-T dn,ace {domain}");
    }
    domain.to_string()
}

async fn query_whois_server(server: &str, query: &str) -> Result<String, String> {
    let op = async {
        let mut stream = TcpStream::connect((server, 43))
            .await
            .map_err(|e| format!("WHOIS connect failed ({server}): {e}"))?;

        stream
            .write_all(format!("{query}\r\n").as_bytes())
            .await
            .map_err(|e| format!("WHOIS write failed ({server}): {e}"))?;

        let mut buffer = Vec::new();
        stream
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| format!("WHOIS read failed ({server}): {e}"))?;

        String::from_utf8(buffer).map_err(|e| format!("WHOIS utf8 decode failed ({server}): {e}"))
    };

    match timeout(Duration::from_millis(WHOIS_TIMEOUT_MS), op).await {
        Ok(result) => result,
        Err(_) => Err("WHOIS timeout".to_string()),
    }
}

async fn fetch_rdap(domain: &str) -> WhoisResult {
    let client = match build_http_client() {
        Ok(client) => client,
        Err(error) => {
            return WhoisResult {
                error: Some(error),
                ..WhoisResult::default()
            }
        }
    };

    let mut endpoints = vec![
        format!("https://rdap.org/domain/{domain}"),
        format!("https://www.rdap.net/domain/{domain}"),
    ];

    match domain.split('.').next_back().map(|t| t.to_lowercase()) {
        Some(tld) if tld == "de" => endpoints.push(format!("https://rdap.nic.de/domain/{domain}")),
        Some(tld) if tld == "uk" => endpoints.push(format!("https://rdap.nominet.uk/domain/{domain}")),
        Some(tld) if tld == "fr" => endpoints.push(format!("https://rdap.afnic.fr/domain/{domain}")),
        _ => {}
    }

    let mut payload: Option<Value> = None;
    let mut errors: Vec<String> = Vec::new();

    for endpoint in endpoints {
        match client.get(&endpoint).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    errors.push(format!("{} HTTP {}", endpoint.split("/domain/").next().unwrap_or(&endpoint), response.status()));
                    continue;
                }

                match response.json::<Value>().await {
                    Ok(value) => {
                        payload = Some(value);
                        break;
                    }
                    Err(error) => {
                        errors.push(format!("{} fetch: {}", endpoint.split("/domain/").next().unwrap_or(&endpoint), error));
                    }
                }
            }
            Err(error) => {
                errors.push(format!("{} fetch: {}", endpoint.split("/domain/").next().unwrap_or(&endpoint), error));
            }
        }
    }

    let Some(payload) = payload else {
        return WhoisResult {
            error: Some(if errors.is_empty() {
                "RDAP lookup failed".to_string()
            } else {
                format!("RDAP failed: {}", errors.join("; "))
            }),
            ..WhoisResult::default()
        };
    };

    let entities = payload
        .get("entities")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let registrar_entity = entities.iter().find(|entity| has_role(entity, "registrar"));
    let abuse_entity = entities
        .iter()
        .find(|entity| has_role(entity, "abuse") || has_role(entity, "technical"));

    WhoisResult {
        registrar: extract_vcard_text(registrar_entity, "fn")
            .or_else(|| extract_vcard_text(registrar_entity, "org"))
            .or_else(|| payload.get("registrarName").and_then(|v| v.as_str()).map(|s| s.to_string())),
        created_at: get_event_date(payload.get("events"), &["registration"]),
        updated_at: get_event_date(payload.get("events"), &["last changed"]),
        expires_at: get_event_date(payload.get("events"), &["expiration", "expiration date", "expiry"]),
        abuse_email: extract_vcard_text(abuse_entity, "email"),
        server: payload.get("port43").and_then(|v| v.as_str()).map(|s| s.to_string()),
        name_servers: payload
            .get("nameservers")
            .and_then(|v| v.as_array())
            .map(|servers| {
                dedupe_strings_sorted(
                    servers
                        .iter()
                        .filter_map(|server| server.get("ldhName").and_then(|v| v.as_str()).map(|s| s.to_string()))
                        .collect(),
                )
            })
            .filter(|values| !values.is_empty()),
        statuses: payload
            .get("status")
            .and_then(|v| v.as_array())
            .map(|statuses| {
                statuses
                    .iter()
                    .filter_map(|status| status.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .filter(|values| !values.is_empty()),
        raw_text: None,
        error: None,
    }
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|roles| {
            roles
                .iter()
                .any(|candidate| candidate.as_str().map(|s| s.eq_ignore_ascii_case(role)).unwrap_or(false))
        })
        .unwrap_or(false)
}

fn get_event_date(events: Option<&Value>, actions: &[&str]) -> Option<String> {
    let events = events?.as_array()?;

    for event in events {
        let action = event
            .get("eventAction")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_lowercase();
        let date = event.get("eventDate").and_then(|v| v.as_str());

        if actions.iter().any(|candidate| action == candidate.to_lowercase()) {
            if let Some(date) = date {
                return Some(date.to_string());
            }
        }
    }

    None
}

fn extract_vcard_text(entity: Option<&Value>, field_name: &str) -> Option<String> {
    let entity = entity?;
    let card = entity.get("vcardArray")?.as_array()?;
    let fields = card.get(1)?.as_array()?;

    for field in fields {
        let entry = field.as_array()?;
        if entry.get(0)?.as_str()? != field_name {
            continue;
        }
        if let Some(value) = entry.get(3).and_then(|v| v.as_str()) {
            return Some(value.to_string());
        }
    }

    None
}
