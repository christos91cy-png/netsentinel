use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub type DbPool = Arc<Mutex<Connection>>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanSummary {
    pub id: i64,
    pub target: String,
    pub scan_type: String,
    pub started_at: String,
    pub port_count: i64,
    pub vuln_count: i64,
}

pub fn init_db(path: &str) -> Result<DbPool> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            started_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            version TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            port INTEGER,
            script_id TEXT NOT NULL,
            output TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS saved_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            target TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scan_ports_scan_id ON scan_ports(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulns_scan_id ON scan_vulns(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
    ",
    )?;

    // Migration: drop raw_output column if it still exists from v0.1.0 schema
    let has_raw_output: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name='raw_output'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if has_raw_output {
        conn.execute_batch("ALTER TABLE scans DROP COLUMN raw_output;")?;
    }

    Ok(Arc::new(Mutex::new(conn)))
}

pub fn save_scan(
    pool: &DbPool,
    target: &str,
    scan_type: &str,
    started_at: &str,
    ports: &[crate::scanner::Port],
    vulns: &[crate::scanner::Vuln],
) -> Result<i64> {
    let conn = pool.lock().unwrap();
    conn.execute(
        "INSERT INTO scans (target, scan_type, started_at) VALUES (?1, ?2, ?3)",
        params![target, scan_type, started_at],
    )?;
    let scan_id = conn.last_insert_rowid();

    for p in ports {
        conn.execute(
            "INSERT INTO scan_ports (scan_id, port, protocol, state, service, version) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![scan_id, p.port, p.protocol, p.state, p.service, p.version],
        )?;
    }

    for v in vulns {
        conn.execute(
            "INSERT INTO scan_vulns (scan_id, port, script_id, output) VALUES (?1, ?2, ?3, ?4)",
            params![scan_id, v.port, v.script_id, v.output],
        )?;
    }

    Ok(scan_id)
}

pub fn delete_scan(pool: &DbPool, id: i64) -> Result<()> {
    let conn = pool.lock().unwrap();
    conn.execute("DELETE FROM scan_vulns WHERE scan_id = ?1", params![id])?;
    conn.execute("DELETE FROM scan_ports WHERE scan_id = ?1", params![id])?;
    conn.execute("DELETE FROM scans WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn get_scan_history(pool: &DbPool) -> Result<Vec<ScanSummary>> {
    let conn = pool.lock().unwrap();
    let mut stmt = conn.prepare(
        "
        SELECT s.id, s.target, s.scan_type, s.started_at,
               COUNT(DISTINCT p.id) as port_count,
               COUNT(DISTINCT v.id) as vuln_count
        FROM scans s
        LEFT JOIN scan_ports p ON p.scan_id = s.id
        LEFT JOIN scan_vulns v ON v.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT 100
    ",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ScanSummary {
            id: row.get(0)?,
            target: row.get(1)?,
            scan_type: row.get(2)?,
            started_at: row.get(3)?,
            port_count: row.get(4)?,
            vuln_count: row.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn get_scan_detail(pool: &DbPool, id: i64) -> Result<Option<crate::scanner::ScanResult>> {
    let conn = pool.lock().unwrap();

    let scan: Option<(String, String, String)> = conn
        .query_row(
            "SELECT target, scan_type, started_at FROM scans WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .ok();

    let Some((target, scan_type, started_at)) = scan else {
        return Ok(None);
    };

    let mut port_stmt = conn.prepare(
        "SELECT port, protocol, state, service, version FROM scan_ports WHERE scan_id = ?1",
    )?;
    let ports: Vec<crate::scanner::Port> = port_stmt
        .query_map(params![id], |row| {
            Ok(crate::scanner::Port {
                port: row.get(0)?,
                protocol: row.get(1)?,
                state: row.get(2)?,
                service: row.get(3)?,
                version: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    let mut vuln_stmt =
        conn.prepare("SELECT port, script_id, output FROM scan_vulns WHERE scan_id = ?1")?;
    let vulns: Vec<crate::scanner::Vuln> = vuln_stmt
        .query_map(params![id], |row| {
            Ok(crate::scanner::Vuln {
                port: row.get(0)?,
                script_id: row.get(1)?,
                output: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(crate::scanner::ScanResult {
        target,
        scan_type,
        started_at,
        ports,
        vulns,
        os_guess: None,
    }))
}
