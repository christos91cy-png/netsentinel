mod cve;
mod database;
mod scanner;

use cve::{CveItem, CveSearchResult};
use database::{DbPool, ScanSummary};
use scanner::ScanResult;
use tauri::State;

struct AppState {
    db: DbPool,
}

#[tauri::command]
async fn run_scan(
    state: State<'_, AppState>,
    target: String,
    scan_type: String,
) -> Result<ScanResult, String> {
    let result = tokio::task::spawn_blocking(move || scanner::run_nmap_scan(&target, &scan_type))
        .await
        .map_err(|e| format!("Task error: {e}"))??;

    let started_at = result.started_at.clone();
    let raw = serde_json::to_string(&result).unwrap_or_default();

    database::save_scan(
        &state.db,
        &result.target,
        &result.scan_type,
        &started_at,
        &raw,
        &result.ports,
        &result.vulns,
    )
    .map_err(|e| format!("DB error: {e}"))?;

    Ok(result)
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
async fn search_cves(keyword: String, page: u32) -> Result<CveSearchResult, String> {
    cve::search_cves(&keyword, page).await
}

#[tauri::command]
async fn get_cve(cve_id: String) -> Result<CveItem, String> {
    cve::get_cve(&cve_id).await
}

pub fn run() {
    let db_path = dirs_next();
    let db = database::init_db(&db_path).expect("Failed to initialize database");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState { db })
        .invoke_handler(tauri::generate_handler![
            run_scan,
            get_scan_history,
            get_scan_detail,
            search_cves,
            get_cve,
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
