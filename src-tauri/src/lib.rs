mod cve;
mod database;
mod diff;
mod scanner;
mod shodan;
mod threat_intel;

use cve::{CveItem, CveSearchResult};
use database::{DbPool, ScanSummary};
use scanner::ScanResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{Emitter, Manager, State};

struct AppState {
    db: DbPool,
    http: reqwest::Client,
    scanning: Arc<AtomicBool>,
    cancel_flag: Arc<AtomicBool>,
}

#[tauri::command]
async fn run_scan(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    target: String,
    scan_type: String,
) -> Result<ScanResult, String> {
    if state.scanning.load(Ordering::Relaxed) {
        return Err("A scan is already running".to_string());
    }
    state.scanning.store(true, Ordering::Relaxed);
    state.cancel_flag.store(false, Ordering::Relaxed);

    let _ = app.emit(
        "scan:start",
        serde_json::json!({ "target": &target, "scan_type": &scan_type }),
    );

    let result =
        scanner::run_nmap_scan_async(&target, &scan_type, &app, state.cancel_flag.clone()).await;
    state.scanning.store(false, Ordering::Relaxed);

    match result {
        Ok(scan_result) => {
            let started_at = scan_result.started_at.clone();
            database::save_scan(
                &state.db,
                &scan_result.target,
                &scan_result.scan_type,
                &started_at,
                &scan_result.ports,
                &scan_result.vulns,
            )
            .map_err(|e| format!("DB error: {e}"))?;
            let _ = app.emit("scan:complete", &scan_result);
            Ok(scan_result)
        }
        Err(e) => {
            let _ = app.emit("scan:error", serde_json::json!({ "error": &e }));
            Err(e)
        }
    }
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_flag.store(true, Ordering::Relaxed);
    state.scanning.store(false, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
fn get_scan_history(state: State<'_, AppState>) -> Result<Vec<ScanSummary>, String> {
    database::get_scan_history(&state.db).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_scan_detail(state: State<'_, AppState>, id: i64) -> Result<Option<ScanResult>, String> {
    database::get_scan_detail(&state.db, id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn search_cves(
    state: State<'_, AppState>,
    keyword: String,
    page: u32,
) -> Result<CveSearchResult, String> {
    cve::search_cves(&state.http, &keyword, page).await
}

#[tauri::command]
async fn get_cve(state: State<'_, AppState>, cve_id: String) -> Result<CveItem, String> {
    cve::get_cve(&state.http, &cve_id).await
}

#[tauri::command]
async fn lookup_shodan(
    state: State<'_, AppState>,
    ip: String,
) -> Result<shodan::ShodanHost, String> {
    shodan::lookup(&state.http, &ip).await
}

#[tauri::command]
fn export_scan_json(state: State<'_, AppState>, id: i64) -> Result<String, String> {
    let result = database::get_scan_detail(&state.db, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Scan not found".to_string())?;
    let content = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    let path = downloads_path(&format!("scan-{id}.json"));
    std::fs::write(&path, &content).map_err(|e| e.to_string())?;
    Ok(path)
}

#[tauri::command]
fn export_scan_csv(state: State<'_, AppState>, id: i64) -> Result<String, String> {
    let result = database::get_scan_detail(&state.db, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Scan not found".to_string())?;
    let mut csv = String::from("port,protocol,state,service,version\n");
    for p in &result.ports {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            p.port,
            p.protocol.as_str(),
            p.state.as_str(),
            p.service.as_deref().unwrap_or(""),
            p.version.as_deref().unwrap_or("")
        ));
    }
    let path = downloads_path(&format!("scan-{id}.csv"));
    std::fs::write(&path, &csv).map_err(|e| e.to_string())?;
    Ok(path)
}

#[tauri::command]
fn delete_scan(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    database::delete_scan(&state.db, id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn correlate_scan_cves(
    state: State<'_, AppState>,
    id: i64,
) -> Result<Vec<serde_json::Value>, String> {
    let scan = database::get_scan_detail(&state.db, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Scan not found".to_string())?;

    let mut results = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for port in &scan.ports {
        if let Some(service) = &port.service {
            let keyword = if let Some(version) = &port.version {
                format!(
                    "{} {}",
                    service,
                    version.split_whitespace().next().unwrap_or("")
                )
            } else {
                service.clone()
            };
            if keyword.len() < 3 {
                continue;
            }

            match cve::search_cves(&state.http, &keyword, 0).await {
                Ok(result) => {
                    for item in result.items.iter().take(3) {
                        if seen.contains(&item.id) {
                            continue;
                        }
                        seen.insert(item.id.clone());
                        results.push(serde_json::json!({
                            "port": port.port,
                            "service": service,
                            "cve_id": item.id,
                            "description": item.description,
                            "cvss_score": item.cvss_score,
                        }));
                    }
                }
                Err(_) => {}
            }
        }
    }
    Ok(results)
}

#[tauri::command]
async fn check_kev(
    state: State<'_, AppState>,
    cve_ids: Vec<String>,
) -> Result<Vec<threat_intel::KevEntry>, String> {
    threat_intel::check_kev(&state.http, cve_ids).await
}

#[tauri::command]
async fn lookup_epss(
    state: State<'_, AppState>,
    cve_ids: Vec<String>,
) -> Result<Vec<threat_intel::EpssEntry>, String> {
    threat_intel::lookup_epss(&state.http, cve_ids).await
}

#[tauri::command]
fn diff_scans(state: State<'_, AppState>, id_a: i64, id_b: i64) -> Result<diff::ScanDiff, String> {
    diff::diff_scans(&state.db, id_a, id_b)
}

pub fn run() {
    let db_path = dirs_next();
    let db = database::init_db(&db_path).expect("Failed to initialize database");
    let http = reqwest::Client::builder().build().unwrap();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            db,
            http,
            scanning: Arc::new(AtomicBool::new(false)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        })
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();
            let img = image::load_from_memory(include_bytes!("../icons/icon.png"))
                .map_err(|e| e.to_string())?
                .into_rgba8();
            let (w, h) = img.dimensions();
            let icon = tauri::image::Image::new_owned(img.into_raw(), w, h);
            window.set_icon(icon)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            run_scan,
            cancel_scan,
            get_scan_history,
            get_scan_detail,
            search_cves,
            get_cve,
            lookup_shodan,
            export_scan_json,
            export_scan_csv,
            delete_scan,
            correlate_scan_cves,
            check_kev,
            lookup_epss,
            diff_scans,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn dirs_next() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = format!("{home}/.local/share/netsentinel");
    std::fs::create_dir_all(&dir).ok();
    format!("{dir}/netsentinel.db")
}

fn downloads_path(filename: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = format!("{home}/Downloads");
    std::fs::create_dir_all(&dir).ok();
    format!("{dir}/{filename}")
}
