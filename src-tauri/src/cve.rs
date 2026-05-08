use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CveItem {
    pub id: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub severity: Option<String>,
    pub published: String,
    pub last_modified: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveSearchResult {
    pub total: u64,
    pub page: u32,
    pub items: Vec<CveItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: u64,
    vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    published: String,
    last_modified: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v31: Option<Vec<NvdCvssV3>>,
    cvss_metric_v2: Option<Vec<NvdCvssV2>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssV3 {
    cvss_data: NvdCvssData,
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssV2 {
    cvss_data: NvdCvssData,
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssData {
    base_score: f64,
}

const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub async fn search_cves(client: &reqwest::Client, keyword: &str, page: u32) -> Result<CveSearchResult, String> {
    let start_index = page * 20;
    let url = format!(
        "{NVD_BASE}?keywordSearch={}&resultsPerPage=20&startIndex={}",
        urlenccode(keyword),
        start_index
    );

    let resp = client
        .get(&url)
        .header("User-Agent", "NetSentinel/0.1")
        .send()
        .await
        .map_err(|e| format!("NVD request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("NVD API returned status {}", resp.status()));
    }

    let nvd: NvdResponse = resp
        .json()
        .await
        .map_err(|e| format!("NVD parse error: {e}"))?;

    let items = nvd
        .vulnerabilities
        .into_iter()
        .map(|w| {
            let cve = w.cve;
            let description = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_default();

            let (cvss_score, severity) = extract_cvss(&cve.metrics);

            CveItem {
                id: cve.id,
                description,
                cvss_score,
                severity,
                published: cve.published,
                last_modified: cve.last_modified,
            }
        })
        .collect();

    Ok(CveSearchResult {
        total: nvd.total_results,
        page,
        items,
    })
}

pub async fn get_cve(client: &reqwest::Client, cve_id: &str) -> Result<CveItem, String> {
    let url = format!("{NVD_BASE}?cveId={cve_id}");

    let resp = client
        .get(&url)
        .header("User-Agent", "NetSentinel/0.1")
        .send()
        .await
        .map_err(|e| format!("NVD request failed: {e}"))?;

    let nvd: NvdResponse = resp
        .json()
        .await
        .map_err(|e| format!("NVD parse error: {e}"))?;

    nvd.vulnerabilities
        .into_iter()
        .next()
        .map(|w| {
            let cve = w.cve;
            let description = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_default();
            let (cvss_score, severity) = extract_cvss(&cve.metrics);
            CveItem {
                id: cve.id,
                description,
                cvss_score,
                severity,
                published: cve.published,
                last_modified: cve.last_modified,
            }
        })
        .ok_or_else(|| format!("CVE {cve_id} not found"))
}

fn extract_cvss(metrics: &Option<NvdMetrics>) -> (Option<f64>, Option<String>) {
    let Some(m) = metrics else {
        return (None, None);
    };

    if let Some(v3) = &m.cvss_metric_v31 {
        if let Some(first) = v3.first() {
            return (
                Some(first.cvss_data.base_score),
                first.base_severity.clone(),
            );
        }
    }
    if let Some(v2) = &m.cvss_metric_v2 {
        if let Some(first) = v2.first() {
            return (
                Some(first.cvss_data.base_score),
                first.base_severity.clone(),
            );
        }
    }
    (None, None)
}

fn urlenccode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "+".to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}
