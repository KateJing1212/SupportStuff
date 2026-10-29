"""Validation and atomic import of offline F2 ZIP packages."""
import hashlib
import io
import json
import re
import sqlite3
import zipfile

from .db import connect
from .repository import rebuild_mappings


FILES = (
    "cves.jsonl", "cwes.jsonl", "capecs.jsonl", "tactics.jsonl", "techniques.jsonl", "mitigations.jsonl",
    "cve_cwe.jsonl", "cwe_capec.jsonl", "capec_attack.jsonl", "technique_tactics.jsonl",
    "technique_mitigations.jsonl", "cicat_supplements.jsonl",
)
IDS = {
    "cves.jsonl": ("cve_id", re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)),
    "cwes.jsonl": ("cwe_id", re.compile(r"^CWE-\d+$", re.I)),
    "capecs.jsonl": ("capec_id", re.compile(r"^CAPEC-\d+$", re.I)),
    "tactics.jsonl": ("tactic_id", re.compile(r"^TA\d+$", re.I)),
    "techniques.jsonl": ("attack_id", re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)),
    "mitigations.jsonl": ("mitigation_id", re.compile(r"^M\d{4}(?:\.\d{3})?$|^.+$", re.I)),
}
ENTITY_TABLES = {
    "cves.jsonl": "cves", "cwes.jsonl": "cwes", "capecs.jsonl": "capecs",
    "tactics.jsonl": "tactics", "techniques.jsonl": "techniques", "mitigations.jsonl": "mitigations",
}
RELATIONS = {
    "cve_cwe.jsonl": ("cve_cwe", ("cve_id", "cwe_id")),
    "cwe_capec.jsonl": ("cwe_capec", ("cwe_id", "capec_id")),
    "capec_attack.jsonl": ("capec_attack", ("capec_id", "attack_id")),
    "technique_tactics.jsonl": ("technique_tactics", ("attack_id", "tactic_id")),
    "technique_mitigations.jsonl": ("technique_mitigations", ("attack_id", "mitigation_id")),
}


def _rows(raw, filename):
    result = []
    for number, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ValueError("{} 第{}行不是有效 JSON: {}".format(filename, number, exc))
        if not isinstance(item, dict):
            raise ValueError("{} 第{}行必须是 JSON 对象".format(filename, number))
        result.append(item)
    return result


def validate_package(file_bytes):
    try:
        archive = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        raise ValueError("上传文件不是有效 ZIP 包")
    with archive:
        names = set(archive.namelist())
        if "manifest.json" not in names:
            raise ValueError("离线包缺少 manifest.json")
        manifest = json.loads(archive.read("manifest.json").decode("utf-8-sig"))
        if manifest.get("format") != "f2-knowledge-package" or manifest.get("format_version") != 2:
            raise ValueError("不支持的数据包格式或版本")
        for key in ("package_id", "package_version", "imported_by"):
            if not manifest.get(key):
                raise ValueError("manifest 缺少 {}".format(key))
        if not isinstance(manifest.get("sources"), list) or not manifest["sources"]:
            raise ValueError("manifest.sources 必须包含来源")
        source_keys = set()
        for source in manifest["sources"]:
            if not all(source.get(k) for k in ("name", "version", "ref")):
                raise ValueError("每个来源都必须包含 name/version/ref")
            source_keys.add((source["name"], source["version"], source["ref"]))
        file_hashes = manifest.get("files") or {}
        contents = {}
        for filename in FILES:
            if filename not in names:
                raise ValueError("离线包缺少 {}".format(filename))
            expected = (file_hashes.get(filename) or {}).get("sha256")
            raw = archive.read(filename)
            if not expected or hashlib.sha256(raw).hexdigest().lower() != expected.lower():
                raise ValueError("{} 的 SHA-256 缺失或不匹配".format(filename))
            contents[filename] = _rows(raw, filename)
        for filename, (key, pattern) in IDS.items():
            for row in contents[filename]:
                value = row.get(key, "")
                if not pattern.match(str(value)):
                    raise ValueError("{} 中存在无效 {}: {}".format(filename, key, value))
        for filename, rows in contents.items():
            for row in rows:
                if not all(row.get(k) for k in ("source_name", "source_version", "source_ref")):
                    raise ValueError("{} 每条记录必须带来源名称、版本和引用".format(filename))
                if (row["source_name"], row["source_version"], row["source_ref"]) not in source_keys:
                    raise ValueError("{} 记录引用了 manifest 未声明的来源".format(filename))
        return manifest, contents, hashlib.sha256(file_bytes).hexdigest()


def _json_field(row, key):
    value = row.get(key, [])
    if not isinstance(value, list):
        raise ValueError("{} 必须是数组".format(key))
    return json.dumps(value, ensure_ascii=False)


def _upsert_entity(conn, table, key, fields, values):
    present = conn.execute("SELECT 1 FROM {} WHERE {}=?".format(table, key), (values[0],)).fetchone()
    if present:
        assignments = ",".join("{}=?".format(field) for field in fields)
        conn.execute("UPDATE {} SET {} WHERE {}=?".format(table, assignments, key), tuple(values[1:]) + (values[0],))
    else:
        columns = ",".join((key,) + tuple(fields))
        marks = ",".join(["?"] * (len(fields) + 1))
        conn.execute("INSERT INTO {}({}) VALUES({})".format(table, columns, marks), values)


def import_package(db_path, file_bytes):
    manifest, contents, package_hash = validate_package(file_bytes)
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT sha256 FROM package_imports WHERE package_id=?", (manifest["package_id"],)).fetchone()
        if existing and existing["sha256"] == package_hash:
            conn.rollback()
            return {"package_id": manifest["package_id"], "package_version": manifest["package_version"], "unchanged": True}
        conn.execute(
            "INSERT OR REPLACE INTO package_imports(package_id,package_version,package_name,sha256,imported_by) VALUES(?,?,?,?,?)",
            (manifest["package_id"], manifest["package_version"], manifest.get("package_name", ""), package_hash, manifest["imported_by"]),
        )
        for filename, table in ENTITY_TABLES.items():
            for row in contents[filename]:
                common = (row.get("imported_by", manifest["imported_by"]), manifest["package_id"])
                source = (row["source_name"], row["source_version"], row["source_ref"])
                if table == "cves":
                    cve_json_fields = ("affected", "references", "metrics", "problem_types", "record")
                    json_values = tuple(json.dumps(row.get(field, [] if field != "record" else {}), ensure_ascii=False) for field in cve_json_fields)
                    _upsert_entity(conn, table, "cve_id", ("title", "description", "cvss_score", "severity", "cve_state", "date_published", "date_updated", "affected_json", "references_json", "metrics_json", "problem_types_json", "record_json", "cicat_validation_state", "cicat_validation_note", "source_name", "source_version", "source_ref", "imported_by", "package_id"),
                                   (row["cve_id"], row.get("title", ""), row.get("description", ""), row.get("cvss_score"), row.get("severity", ""), row.get("cve_state", ""), row.get("date_published", ""), row.get("date_updated", "")) + json_values + (row.get("cicat_validation_state", "not_compared"), row.get("cicat_validation_note", "")) + source + common)
                elif table == "techniques":
                    _upsert_entity(conn, table, "attack_id", ("name", "description", "tactic_ids", "platforms", "source_name", "source_version", "source_ref", "imported_by", "package_id"),
                                   (row["attack_id"], row.get("name", ""), row.get("description", ""), _json_field(row, "tactic_ids"), _json_field(row, "platforms")) + source + common)
                else:
                    if table == "tactics":
                        key = "tactic_id"
                        fields = ("short_name", "name", "description", "source_name", "source_version", "source_ref", "imported_by", "package_id")
                        values = (row[key], row.get("short_name", ""), row.get("name", ""), row.get("description", "")) + source + common
                    else:
                        key = "cwe_id" if table == "cwes" else "capec_id" if table == "capecs" else "mitigation_id"
                        fields = ("name", "description", "source_name", "source_version", "source_ref", "imported_by", "package_id")
                        values = (row[key], row.get("name", ""), row.get("description", "")) + source + common
                    _upsert_entity(conn, table, key, fields, values)
        for filename, (table, keys) in RELATIONS.items():
            for row in contents[filename]:
                source = (row["source_name"], row["source_version"], row["source_ref"])
                values = tuple(row.get(key) for key in keys)
                if not all(values):
                    raise ValueError("{} 关系缺少键 {}".format(filename, keys))
                columns = ",".join(keys + ("source_name", "source_version", "source_ref", "imported_by"))
                marks = ",".join(["?"] * (len(keys) + 4))
                conn.execute("INSERT OR REPLACE INTO {}({}) VALUES({})".format(table, columns, marks), values + source + (manifest["imported_by"],))
        for row in contents["cicat_supplements.jsonl"]:
            if not all(row.get(k) for k in ("cve_id", "attack_id", "source_name", "source_version", "source_ref")):
                raise ValueError("cicat_supplements.jsonl 记录缺少必填字段")
            conn.execute("INSERT OR REPLACE INTO cve_attack_supplements(cve_id,attack_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)",
                         (row["cve_id"], row["attack_id"], row["source_name"], row["source_version"], row["source_ref"], row.get("imported_by", manifest["imported_by"])))
        rebuild_mappings(conn)
        conn.commit()
        return {"package_id": manifest["package_id"], "package_version": manifest["package_version"], "unchanged": False,
                "counts": {name: len(rows) for name, rows in contents.items()}}
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError("离线包存在重复键或无法解析的关系引用: {}".format(exc))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
