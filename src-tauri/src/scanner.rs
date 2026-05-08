use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use std::process::Command;
use tauri::Emitter;

use tokio::io::AsyncBufReadExt;
use tokio::process::Command as TokioCommand;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Port {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vuln {
    pub port: Option<u16>,
    pub script_id: String,
    pub output: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub target: String,
    pub scan_type: String,
    pub started_at: String,
    pub ports: Vec<Port>,
    pub vulns: Vec<Vuln>,
    pub os_guess: Option<String>,
}


pub async fn run_nmap_scan_async(
    target: &str,
    scan_type: &str,
    app_handle: &tauri::AppHandle,
    cancel_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<ScanResult, String> {
    let nmap_path = which_nmap()?;
    let started_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut base_args: Vec<String> = vec![
        "-oX".to_string(),
        "-".to_string(),
        "--open".to_string(),
        "--stats-every".to_string(),
        "3s".to_string(),
    ];

    let scan_specific: Vec<String> = match scan_type {
        "quick" => vec![
            "-F".to_string(),
            "-sV".to_string(),
            "--version-intensity".to_string(),
            "3".to_string(),
        ],
        "full" => vec![
            "-p-".to_string(),
            "-sV".to_string(),
            "--version-intensity".to_string(),
            "5".to_string(),
        ],
        "vuln" => vec![
            "-sV".to_string(),
            "--script".to_string(),
            "vuln".to_string(),
        ],
        "discover" => vec![
            "-sn".to_string(),
            "--host-timeout".to_string(),
            "30s".to_string(),
        ],
        _ => return Err(format!("Unknown scan type: {scan_type}")),
    };

    base_args.extend(scan_specific);
    base_args.push(target.to_string());
    let full_args = base_args;

    let mut child = TokioCommand::new(&nmap_path)
        .args(&full_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn nmap: {e}"))?;

    let stderr = child.stderr.take().expect("stderr piped");
    let app_clone = app_handle.clone();
    let start = std::time::Instant::now();
    let cancel_clone = cancel_flag.clone();

    tokio::spawn(async move {
        let reader = tokio::io::BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if line.contains("% done") {
                let percent = line
                    .split('%')
                    .next()
                    .and_then(|s| s.split_whitespace().last())
                    .and_then(|s| s.parse::<f32>().ok())
                    .unwrap_or(0.0) as u8;
                let _ = app_clone.emit(
                    "scan:progress",
                    serde_json::json!({
                        "percent": percent,
                        "phase": "Port Scanning",
                        "elapsed_secs": start.elapsed().as_secs()
                    }),
                );
            }
        }
    });

    let cancel_poll = cancel_flag.clone();
    let output = tokio::select! {
        result = child.wait_with_output() => result.map_err(|e| e.to_string())?,
        _ = async {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                if cancel_poll.load(std::sync::atomic::Ordering::Relaxed) { break; }
            }
        } => return Err("Scan cancelled".to_string()),
    };

    let xml = String::from_utf8_lossy(&output.stdout);
    parse_nmap_xml(&xml, target, scan_type, &started_at)
}

fn which_nmap() -> Result<String, String> {
    let output = Command::new("which")
        .arg("nmap")
        .output()
        .map_err(|e| format!("Cannot find nmap: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err("nmap is not installed. Please install it with: sudo apt install nmap".to_string())
    }
}

pub(crate) fn parse_nmap_xml(
    xml: &str,
    target: &str,
    scan_type: &str,
    started_at: &str,
) -> Result<ScanResult, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut ports: Vec<Port> = Vec::new();
    let mut vulns: Vec<Vuln> = Vec::new();

    let mut current_port: Option<u16> = None;
    let mut current_protocol = String::new();
    let mut current_state = String::new();
    let mut current_service: Option<String> = None;
    let mut current_version: Option<String> = None;

    let mut best_os_name: Option<String> = None;
    let mut best_os_accuracy: u32 = 0;

    // discover scan host tracking
    let mut current_host_addr: Option<String> = None;
    let mut current_host_status: Option<String> = None;
    let mut current_host_hostname: Option<String> = None;
    let mut host_index: u16 = 1;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"host" => {
                    current_host_addr = None;
                    current_host_status = None;
                    current_host_hostname = None;
                }
                b"status" => {
                    current_host_status = attr_value(&e, b"state");
                }
                b"address" => {
                    if attr_value(&e, b"addrtype").as_deref() == Some("ipv4") {
                        current_host_addr = attr_value(&e, b"addr");
                    }
                }
                b"hostname" => {
                    if current_host_hostname.is_none() {
                        current_host_hostname = attr_value(&e, b"name");
                    }
                }
                b"port" => {
                    current_port = attr_value(&e, b"portid").and_then(|v| v.parse().ok());
                    current_protocol = attr_value(&e, b"protocol").unwrap_or_default();
                    current_state = String::new();
                    current_service = None;
                    current_version = None;
                }
                b"state" => {
                    current_state = attr_value(&e, b"state").unwrap_or_default();
                }
                b"service" => {
                    let name = attr_value(&e, b"name");
                    let product = attr_value(&e, b"product");
                    let version = attr_value(&e, b"version");
                    current_service = name;
                    current_version = match (product, version) {
                        (Some(p), Some(v)) => Some(format!("{p} {v}")),
                        (Some(p), None) => Some(p),
                        (None, Some(v)) => Some(v),
                        _ => None,
                    };
                }
                b"script" => {
                    let script_id = attr_value(&e, b"id").unwrap_or_default();
                    let output = attr_value(&e, b"output").unwrap_or_default();
                    if !script_id.is_empty() {
                        vulns.push(Vuln {
                            port: current_port,
                            script_id,
                            output,
                        });
                    }
                }
                b"osmatch" => {
                    if let (Some(name), Some(accuracy_str)) = (
                        attr_value(&e, b"name"),
                        attr_value(&e, b"accuracy"),
                    ) {
                        let accuracy: u32 = accuracy_str.parse().unwrap_or(0);
                        if accuracy > best_os_accuracy {
                            best_os_accuracy = accuracy;
                            best_os_name = Some(name);
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"host" => {
                    if scan_type == "discover"
                        && current_host_status.as_deref() == Some("up")
                        && current_host_addr.is_some()
                    {
                        ports.push(Port {
                            port: host_index,
                            protocol: "host".to_string(),
                            state: "up".to_string(),
                            service: current_host_addr.take(),
                            version: current_host_hostname.take(),
                        });
                        host_index += 1;
                    }
                    current_host_addr = None;
                    current_host_status = None;
                    current_host_hostname = None;
                }
                b"port" => {
                    if let Some(port_num) = current_port {
                        ports.push(Port {
                            port: port_num,
                            protocol: current_protocol.clone(),
                            state: current_state.clone(),
                            service: current_service.clone(),
                            version: current_version.clone(),
                        });
                    }
                    current_port = None;
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    let os_guess = best_os_name;

    Ok(ScanResult {
        target: target.to_string(),
        scan_type: scan_type.to_string(),
        started_at: started_at.to_string(),
        ports,
        vulns,
        os_guess,
    })
}

fn attr_value(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_port() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let result = parse_nmap_xml(xml, "192.168.1.1", "quick", "2026-01-01T00:00:00Z");
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.ports.len(), 1);
        assert_eq!(r.ports[0].port, 80);
    }

    #[test]
    fn test_parse_no_ports() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports></ports>
  </host>
</nmaprun>"#;
        let result = parse_nmap_xml(xml, "192.168.1.1", "quick", "2026-01-01T00:00:00Z");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().ports.len(), 0);
    }
}
