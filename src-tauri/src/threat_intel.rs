use reqwest::Client;
use serde::{Deserialize, Serialize};

// CISA Known Exploited Vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
}

#[derive(Debug, Deserialize)]
struct KevFeed {
    vulnerabilities: Vec<KevEntry>,
}

// EPSS score from FIRST
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssEntry {
    pub cve: String,
    pub epss: String,
    pub percentile: String,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssEntry>,
}

pub async fn fetch_kev(client: &Client) -> Result<Vec<KevEntry>, String> {
    let resp = client
        .get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        .send()
        .await
        .map_err(|e| format!("KEV fetch error: {e}"))?;

    let feed: KevFeed = resp
        .json()
        .await
        .map_err(|e| format!("KEV parse error: {e}"))?;

    Ok(feed.vulnerabilities)
}

pub async fn check_kev(client: &Client, cve_ids: Vec<String>) -> Result<Vec<KevEntry>, String> {
    let all = fetch_kev(client).await?;
    let filtered = all
        .into_iter()
        .filter(|entry| cve_ids.contains(&entry.cve_id))
        .collect();
    Ok(filtered)
}

pub async fn lookup_epss(client: &Client, cve_ids: Vec<String>) -> Result<Vec<EpssEntry>, String> {
    if cve_ids.is_empty() {
        return Ok(vec![]);
    }

    let joined = cve_ids.join(",");
    let url = format!("https://api.first.org/data/v1/epss?cve={joined}");

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("EPSS fetch error: {e}"))?;

    let parsed: EpssResponse = resp
        .json()
        .await
        .map_err(|e| format!("EPSS parse error: {e}"))?;

    Ok(parsed.data)
}
