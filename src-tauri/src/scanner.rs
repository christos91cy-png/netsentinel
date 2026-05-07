use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use std::process::Command;

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
}

pub fn run_nmap_scan(target: &str, scan_type: &str) -> Result<ScanResult, String> {
    let nmap_path = which_nmap()?;

    let mut args: Vec<&str> = vec!["-oX", "-", "--open"];

    let extra_args: Vec<String>;
    match scan_type {
        "quick" => {
            extra_args = vec![
                "-F".to_string(),
                "-sV".to_string(),
                "--version-intensity".to_string(),
                "3".to_string(),
            ];
        }
        "full" => {
            extra_args = vec![
                "-p-".to_string(),
                "-sV".to_string(),
                "--version-intensity".to_string(),
                "5".to_string(),
            ];
        }
        "vuln" => {
            extra_args = vec![
                "-sV".to_string(),
                "--script".to_string(),
                "vuln".to_string(),
            ];
        }
        _ => return Err(format!("Unknown scan type: {scan_type}")),
    }

    for a in &extra_args {
        args.push(a.as_str());
    }
    args.push(target);

    let output = Command::new(&nmap_path)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run nmap: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nmap exited with error: {stderr}"));
    }

    let xml = String::from_utf8_lossy(&output.stdout).to_string();
    let started_at = chrono_now();

    parse_nmap_xml(&xml, target, scan_type, &started_at)
        .map_err(|e| format!("Failed to parse nmap output: {e}"))
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

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple ISO-ish timestamp without chrono dependency
    let s = secs;
    let mins = s / 60;
    let hours = mins / 60;
    let days = hours / 24;
    let years = 1970 + days / 365;
    format!("{years}-xx-xx {}:{}:{}", hours % 24, mins % 60, s % 60)
}

fn parse_nmap_xml(
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

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
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
                _ => {}
            },
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"port" {
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
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(ScanResult {
        target: target.to_string(),
        scan_type: scan_type.to_string(),
        started_at: started_at.to_string(),
        ports,
        vulns,
    })
}

fn attr_value(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
}
