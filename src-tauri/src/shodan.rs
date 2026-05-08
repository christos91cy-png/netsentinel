use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShodanHost {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub tags: Vec<String>,
    pub cpes: Vec<String>,
    pub vulns: Vec<String>,
}

pub async fn lookup(client: &Client, ip: &str) -> Result<ShodanHost, String> {
    // Skip private/loopback IPs
    if ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || ip.starts_with("172.")
        || ip == "127.0.0.1"
        || ip == "localhost"
    {
        return Err("Private IP — Shodan lookup skipped".to_string());
    }
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if resp.status() == 404 {
        return Err("No Shodan data for this host".to_string());
    }
    #[derive(Deserialize)]
    struct Raw {
        ip: Option<String>,
        ports: Option<Vec<u16>>,
        hostnames: Option<Vec<String>>,
        tags: Option<Vec<String>>,
        cpes: Option<Vec<String>>,
        vulns: Option<Vec<String>>,
    }
    let raw: Raw = resp.json().await.map_err(|e| e.to_string())?;
    Ok(ShodanHost {
        ip: raw.ip.unwrap_or_else(|| ip.to_string()),
        ports: raw.ports.unwrap_or_default(),
        hostnames: raw.hostnames.unwrap_or_default(),
        tags: raw.tags.unwrap_or_default(),
        cpes: raw.cpes.unwrap_or_default(),
        vulns: raw.vulns.unwrap_or_default(),
    })
}
