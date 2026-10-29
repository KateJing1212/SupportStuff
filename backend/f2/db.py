"""SQLite schema and connection helpers."""
import os
import sqlite3


SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS package_imports (
 package_id TEXT PRIMARY KEY, package_version TEXT NOT NULL, package_name TEXT,
 sha256 TEXT NOT NULL, imported_by TEXT NOT NULL, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cves (
 cve_id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 cvss_score REAL, severity TEXT NOT NULL DEFAULT '', mapping_state TEXT NOT NULL DEFAULT 'unmapped',
 mapping_note TEXT NOT NULL DEFAULT '尚无完整 CVE→CWE→CAPEC→ATT&CK 关系链',
 cve_state TEXT NOT NULL DEFAULT '', date_published TEXT NOT NULL DEFAULT '', date_updated TEXT NOT NULL DEFAULT '',
 affected_json TEXT NOT NULL DEFAULT '[]', references_json TEXT NOT NULL DEFAULT '[]',
 metrics_json TEXT NOT NULL DEFAULT '[]', problem_types_json TEXT NOT NULL DEFAULT '[]',
 record_json TEXT NOT NULL DEFAULT '{}', cicat_validation_state TEXT NOT NULL DEFAULT 'not_compared',
 cicat_validation_note TEXT NOT NULL DEFAULT '',
 source_name TEXT NOT NULL, source_version TEXT NOT NULL, source_ref TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '', package_id TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cwes (
 cwe_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 source_name TEXT NOT NULL, source_version TEXT NOT NULL, source_ref TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '', package_id TEXT
);
CREATE TABLE IF NOT EXISTS capecs (
 capec_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 source_name TEXT NOT NULL, source_version TEXT NOT NULL, source_ref TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '', package_id TEXT
);
CREATE TABLE IF NOT EXISTS techniques (
 attack_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 tactic_ids TEXT NOT NULL DEFAULT '[]', platforms TEXT NOT NULL DEFAULT '[]',
 source_name TEXT NOT NULL, source_version TEXT NOT NULL, source_ref TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '', package_id TEXT
);
CREATE TABLE IF NOT EXISTS tactics (
 tactic_id TEXT PRIMARY KEY, short_name TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 source_name TEXT NOT NULL, source_version TEXT NOT NULL, source_ref TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '', package_id TEXT
);
CREATE TABLE IF NOT EXISTS technique_tactics (
 attack_id TEXT NOT NULL, tactic_id TEXT NOT NULL, source_name TEXT NOT NULL,
 source_version TEXT NOT NULL, source_ref TEXT NOT NULL, imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(attack_id,tactic_id), FOREIGN KEY(attack_id) REFERENCES techniques(attack_id),
 FOREIGN KEY(tactic_id) REFERENCES tactics(tactic_id)
);
CREATE TABLE IF NOT EXISTS mitigations (
 mitigation_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 source_name TEXT NOT NULL, source_version TEXT NOT NULL, source_ref TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '', package_id TEXT
);
CREATE TABLE IF NOT EXISTS cve_cwe (
 cve_id TEXT NOT NULL, cwe_id TEXT NOT NULL, source_name TEXT NOT NULL,
 source_version TEXT NOT NULL, source_ref TEXT NOT NULL, imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(cve_id,cwe_id), FOREIGN KEY(cve_id) REFERENCES cves(cve_id),
 FOREIGN KEY(cwe_id) REFERENCES cwes(cwe_id)
);
CREATE TABLE IF NOT EXISTS cwe_capec (
 cwe_id TEXT NOT NULL, capec_id TEXT NOT NULL, source_name TEXT NOT NULL,
 source_version TEXT NOT NULL, source_ref TEXT NOT NULL, imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(cwe_id,capec_id), FOREIGN KEY(cwe_id) REFERENCES cwes(cwe_id),
 FOREIGN KEY(capec_id) REFERENCES capecs(capec_id)
);
CREATE TABLE IF NOT EXISTS capec_attack (
 capec_id TEXT NOT NULL, attack_id TEXT NOT NULL, source_name TEXT NOT NULL,
 source_version TEXT NOT NULL, source_ref TEXT NOT NULL, imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(capec_id,attack_id), FOREIGN KEY(capec_id) REFERENCES capecs(capec_id),
 FOREIGN KEY(attack_id) REFERENCES techniques(attack_id)
);
CREATE TABLE IF NOT EXISTS technique_mitigations (
 attack_id TEXT NOT NULL, mitigation_id TEXT NOT NULL, source_name TEXT NOT NULL,
 source_version TEXT NOT NULL, source_ref TEXT NOT NULL, imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(attack_id,mitigation_id), FOREIGN KEY(attack_id) REFERENCES techniques(attack_id),
 FOREIGN KEY(mitigation_id) REFERENCES mitigations(mitigation_id)
);
CREATE TABLE IF NOT EXISTS cve_attack_mappings (
 mapping_id TEXT PRIMARY KEY, cve_id TEXT NOT NULL, cwe_id TEXT, capec_id TEXT,
 attack_id TEXT NOT NULL, mapping_method TEXT NOT NULL, mapping_state TEXT NOT NULL,
 evidence_json TEXT NOT NULL, source_versions_json TEXT NOT NULL, source_refs_json TEXT NOT NULL,
 imported_by TEXT NOT NULL DEFAULT '',
 FOREIGN KEY(cve_id) REFERENCES cves(cve_id), FOREIGN KEY(cwe_id) REFERENCES cwes(cwe_id),
 FOREIGN KEY(capec_id) REFERENCES capecs(capec_id), FOREIGN KEY(attack_id) REFERENCES techniques(attack_id),
 UNIQUE(cve_id,cwe_id,capec_id,attack_id)
);
CREATE TABLE IF NOT EXISTS cve_attack_supplements (
 cve_id TEXT NOT NULL, attack_id TEXT NOT NULL, source_name TEXT NOT NULL,
 source_version TEXT NOT NULL, source_ref TEXT NOT NULL, imported_by TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(cve_id,attack_id), FOREIGN KEY(cve_id) REFERENCES cves(cve_id),
 FOREIGN KEY(attack_id) REFERENCES techniques(attack_id)
);
CREATE INDEX IF NOT EXISTS idx_cves_state ON cves(mapping_state);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(date_published DESC,cve_id DESC);
CREATE INDEX IF NOT EXISTS idx_mapping_cve ON cve_attack_mappings(cve_id);
CREATE INDEX IF NOT EXISTS idx_mapping_attack ON cve_attack_mappings(attack_id);
"""


def connect(path):
    directory = os.path.dirname(os.path.abspath(path))
    if not path.startswith("file:") and directory and not os.path.isdir(directory):
        os.makedirs(directory)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def initialize_database(path):
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('schema_version',?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
    finally:
        conn.close()
