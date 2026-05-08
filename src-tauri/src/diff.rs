use crate::database::DbPool;
use crate::scanner::{Port, Vuln};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct PortDiff {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanDiff {
    pub scan_a_id: i64,
    pub scan_b_id: i64,
    pub scan_a_target: String,
    pub scan_b_target: String,
    pub scan_a_date: String,
    pub scan_b_date: String,
    pub new_ports: Vec<PortDiff>,
    pub closed_ports: Vec<PortDiff>,
    pub unchanged_ports: Vec<PortDiff>,
    pub new_vulns: Vec<Vuln>,
    pub resolved_vulns: Vec<Vuln>,
}

fn port_to_diff(p: &Port) -> PortDiff {
    PortDiff {
        port: p.port,
        protocol: p.protocol.clone(),
        service: p.service.clone(),
        version: p.version.clone(),
        state: p.state.clone(),
    }
}

pub fn diff_scans(db: &DbPool, id_a: i64, id_b: i64) -> Result<ScanDiff, String> {
    let scan_a = crate::database::get_scan_detail(db, id_a)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Scan not found: id={id_a}"))?;

    let scan_b = crate::database::get_scan_detail(db, id_b)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Scan not found: id={id_b}"))?;

    // Build port key sets: (port, protocol)
    let keys_a: HashSet<(u16, String)> = scan_a
        .ports
        .iter()
        .map(|p| (p.port, p.protocol.clone()))
        .collect();
    let keys_b: HashSet<(u16, String)> = scan_b
        .ports
        .iter()
        .map(|p| (p.port, p.protocol.clone()))
        .collect();

    let new_ports = scan_b
        .ports
        .iter()
        .filter(|p| !keys_a.contains(&(p.port, p.protocol.clone())))
        .map(port_to_diff)
        .collect();

    let closed_ports = scan_a
        .ports
        .iter()
        .filter(|p| !keys_b.contains(&(p.port, p.protocol.clone())))
        .map(port_to_diff)
        .collect();

    let unchanged_ports = scan_b
        .ports
        .iter()
        .filter(|p| keys_a.contains(&(p.port, p.protocol.clone())))
        .map(port_to_diff)
        .collect();

    // Compare vulns by script_id
    let script_ids_a: HashSet<&str> = scan_a.vulns.iter().map(|v| v.script_id.as_str()).collect();
    let script_ids_b: HashSet<&str> = scan_b.vulns.iter().map(|v| v.script_id.as_str()).collect();

    let new_vulns = scan_b
        .vulns
        .iter()
        .filter(|v| !script_ids_a.contains(v.script_id.as_str()))
        .cloned()
        .collect();

    let resolved_vulns = scan_a
        .vulns
        .iter()
        .filter(|v| !script_ids_b.contains(v.script_id.as_str()))
        .cloned()
        .collect();

    Ok(ScanDiff {
        scan_a_id: id_a,
        scan_b_id: id_b,
        scan_a_target: scan_a.target,
        scan_b_target: scan_b.target,
        scan_a_date: scan_a.started_at,
        scan_b_date: scan_b.started_at,
        new_ports,
        closed_ports,
        unchanged_ports,
        new_vulns,
        resolved_vulns,
    })
}
