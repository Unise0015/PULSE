import sqlite3
from typing import Optional
from pathlib import Path
from pulse.config import get_config_dir

DB_NAME = "posture_history.db"

def get_db_path() -> Path:
    return get_config_dir() / DB_NAME

def init_db(db_path_override: Optional[Path] = None) -> None:
    """Initialize the posture history database and create tables if they don't exist."""
    db_path = db_path_override or get_db_path()
    
    # Connect will create the file if it doesn't exist
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Schema as per PRD
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_runs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
                hostname      TEXT,
                tool_version  TEXT,
                attack_surface_score INTEGER,
                scan_duration_seconds REAL,
                packages_scanned INTEGER,
                vulnerabilities_found INTEGER,
                kev_matches INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_events (
                scan_run_id   INTEGER,
                cve_id        TEXT,
                package       TEXT,
                status        TEXT,   -- 'new' | 'persisting' | 'remediated'
                risk_score    INTEGER,
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
            )
        ''')
        
        # M6.6 & M7.4 Migrations
        columns_to_add = [
            ("cvss_score", "REAL DEFAULT 0.0"),
            ("cvss_severity", "TEXT DEFAULT 'UNKNOWN'"),
            ("epss_score", "REAL DEFAULT 0.0"),
            ("epss_percent", "TEXT DEFAULT '0%'"),
            ("latest_version", "TEXT DEFAULT 'Unknown'"),
            ("description", "TEXT DEFAULT ''"),
            ("kev_match", "INTEGER DEFAULT 0"),
            ("cwe", "TEXT DEFAULT ''"),
            ("cvss_vector", "TEXT DEFAULT ''"),
            ("nvd_url", "TEXT DEFAULT ''"),
            ("public_poc", "INTEGER DEFAULT 0"),
            ("poc_source", "TEXT DEFAULT NULL"),
            ("exploit_maturity", "TEXT DEFAULT 'Unknown'"),
            ("threat_level", "TEXT DEFAULT 'Low'")
        ]
        
        for col_name, col_def in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE cve_events ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass # Column already exists
        
        scan_runs_columns = [
            ("target_type", "TEXT DEFAULT 'global'"),
            ("target_id", "TEXT DEFAULT 'global'"),
            ("target_fingerprint", "TEXT DEFAULT ''"),
            ("report_dir", "TEXT DEFAULT NULL"),
            ("scan_integrity", "TEXT DEFAULT NULL"),
            ("provider_status_json", "TEXT DEFAULT NULL"),
            ("warnings_json", "TEXT DEFAULT NULL"),
            ("recommendations_json", "TEXT DEFAULT NULL")
        ]
        for col_name, col_def in scan_runs_columns:
            try:
                cursor.execute(f"ALTER TABLE scan_runs ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass
        
        
        # Cache Tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS osv_cache (
                query_key     TEXT PRIMARY KEY,
                response_json TEXT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nvd_cache (
                cve_id        TEXT PRIMARY KEY,
                response_json TEXT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS epss_cache (
                cve_id        TEXT PRIMARY KEY,
                epss_score    REAL,
                epss_percent  TEXT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kev_metadata (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                last_updated  DATETIME DEFAULT CURRENT_TIMESTAMP,
                catalog_json  TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS package_registry_cache (
                pkg_key       TEXT PRIMARY KEY,
                latest_version TEXT,
                release_date  TEXT,
                homepage      TEXT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ecosystem_detection_cache (
                package_name  TEXT PRIMARY KEY,
                ecosystem     TEXT,
                detected_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ecosystem_resolution_cache (
                package_name  TEXT PRIMARY KEY,
                ecosystem     TEXT,
                detected_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS package_version_cache (
                ecosystem        TEXT,
                package_name     TEXT,
                versions_json    TEXT,
                latest_stable    TEXT,
                latest_lts       TEXT,
                registry_payload TEXT,
                schema_version   INTEGER DEFAULT 1,
                cache_hits       INTEGER DEFAULT 0,
                cache_misses     INTEGER DEFAULT 0,
                last_error       TEXT,
                last_success     DATETIME,
                updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(ecosystem, package_name)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_technologies (
                scan_run_id           INTEGER,
                name                  TEXT,
                version               TEXT,
                category              TEXT,
                confidence            INTEGER,
                confidence_band       TEXT,
                evidence_count        INTEGER,
                raw_match_count       INTEGER,
                version_status        TEXT,
                evidence_json         TEXT,
                version_evidence_json TEXT,
                version_confidence    INTEGER,
                signature_id          TEXT,
                signature_version     TEXT,
                parent                TEXT,
                children_json         TEXT,
                cpe_candidates_json   TEXT,
                ecosystem             TEXT,
                correlation_supported INTEGER,
                detection_mode        TEXT,
                technology_key        TEXT,
                fingerprint_hash      TEXT,
                first_seen_scan_id    INTEGER,
                last_seen_scan_id     INTEGER,
                schema_version        TEXT DEFAULT '1.0',
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_technologies_scan_run ON scan_technologies(scan_run_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_technologies_hashes ON scan_technologies(technology_key, fingerprint_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_technologies_lifecycle ON scan_technologies(first_seen_scan_id, last_seen_scan_id)')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_artifacts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       TEXT NOT NULL,
                format        TEXT NOT NULL,
                path          TEXT NOT NULL,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_size     INTEGER DEFAULT 0,
                status        TEXT DEFAULT 'AVAILABLE',
                sha256        TEXT DEFAULT NULL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_report_artifacts_scan ON report_artifacts(scan_id, format)')
        
        # ── CPE Dictionary Cache (Tier 2 results, 30-day TTL) ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpe_dictionary_cache (
                keyword       TEXT NOT NULL,
                cpe_23_uri    TEXT NOT NULL,
                vendor        TEXT,
                product       TEXT,
                confidence    INTEGER DEFAULT 0,
                deprecated    INTEGER DEFAULT 0,
                titles_json   TEXT,
                refs_json     TEXT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(keyword, cpe_23_uri)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cpe_dict_keyword ON cpe_dictionary_cache(keyword)')
        
        # ── Dynamic CPE Crosswalk (auto-promoted high-confidence Tier 2 hits, 90-day TTL) ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dynamic_cpe_crosswalk (
                ecosystem     TEXT NOT NULL,
                package_name  TEXT NOT NULL,
                cpe_23_uri    TEXT NOT NULL,
                vendor        TEXT,
                product       TEXT,
                confidence    INTEGER DEFAULT 0,
                promoted_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(ecosystem, package_name)
            )
        ''')
        
        # ── cve_events lifecycle columns for Reserved CVE reconciliation ──
        cve_events_lifecycle_cols = [
            ("vuln_status", "TEXT DEFAULT NULL"),
            ("reconciled_at", "DATETIME DEFAULT NULL"),
        ]
        for col_name, col_def in cve_events_lifecycle_cols:
            try:
                cursor.execute(f"ALTER TABLE cve_events ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        conn.commit()
