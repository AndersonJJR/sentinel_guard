-- Initial database schema for Sentinel Guard (Milestone 1)

CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    quarantine_dir TEXT NOT NULL,
    approved_dir TEXT NOT NULL,
    clamd_socket_path TEXT NOT NULL,
    suricata_eve_path TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    source_path TEXT NOT NULL,
    destination_path TEXT,
    sha256_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    detected_mime TEXT,
    verdict_type TEXT NOT NULL,
    verdict_detail TEXT,
    inspected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quarantine_logs_inspected_at
    ON quarantine_logs (inspected_at DESC, id DESC);
