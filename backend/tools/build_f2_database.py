"""Build a fresh F2 SQLite database from official offline snapshots."""
import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
import zipfile


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
from f2.db import connect, initialize_database  # noqa: E402
from f2.repository import rebuild_mappings  # noqa: E402


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CWE_RE = re.compile(r"^CWE-?(\d+)$", re.I)
CAPEC_ATTACK_RE = re.compile(r"ENTRY ID\s*:\s*(\d{4}(?:\.\d{3})?)", re.I)
NS = {"cwe": "http://cwe.mitre.org/cwe-7", "capec": "http://capec.mitre.org/capec-3"}


def _source_row(values, name, version, ref, imported_by="F2 offline build"):
    return tuple(values) + (name, version, ref, imported_by)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _text(node, path):
    found = node.find(path)
    return "" if found is None or found.text is None else found.text.strip()


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _first_english(items):
    for item in items or []:
        if item.get("lang", "en").lower().startswith("en") and item.get("value"):
            return item["value"]
    return (items or [{}])[0].get("value", "")


def _cwe_ids(value):
    result = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in ("cweid", "cwe_id", "weaknessid") and isinstance(child, (str, int)):
                match = CWE_RE.match(str(child))
                if match:
                    result.add("CWE-" + match.group(1))
            result.update(_cwe_ids(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_cwe_ids(child))
    return result


def _cvss(containers):
    metrics, candidates = [], []
    for container in containers:
        for metric in container.get("metrics", []) or []:
            metrics.append(metric)
            stack = [metric]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    score = item.get("baseScore")
                    if isinstance(score, (int, float)):
                        candidates.append((float(score), str(item.get("baseSeverity", ""))))
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
    if not candidates:
        return None, "", metrics
    score, severity = max(candidates, key=lambda pair: pair[0])
    if not severity:
        severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return score, severity, metrics


def _insert_many(conn, sql, rows, batch=1000):
    pending = []
    for row in rows:
        pending.append(row)
        if len(pending) >= batch:
            conn.executemany(sql, pending)
            pending = []
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
    if pending:
        conn.executemany(sql, pending)


def _external_id(obj, source_name):
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name", "").lower() == source_name.lower() and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return ""


def build(args):
    required = (args.cve_zip, args.attack_json, args.cwe_zip, args.capec_zip, args.capec_attack_zip, args.cicat_jsonl)
    missing = [path for path in required if not os.path.isfile(path)]
    if missing:
        raise IOError("缺少输入文件: " + ", ".join(missing))
    if os.path.exists(args.db):
        raise IOError("目标数据库已存在；请指定一个新路径: " + args.db)

    staging = args.db + ".building-" + uuid.uuid4().hex
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    versions = {
        "CVE List V5": args.cve_version,
        "MITRE ATT&CK Enterprise": args.attack_version,
        "CWE": "4.20",
        "CAPEC": "3.9",
    }
    hashes = {name: _sha(path) for name, path in zip(("cve", "attack", "cwe", "capec", "capec_attack", "cicat"), required)}
    print("已计算输入快照 SHA-256，开始解析官方离线数据。", flush=True)
    versions["CVE List V5"] = args.cve_version + "@sha256:" + hashes["cve"]
    conn = None
    counts = {}
    try:
        initialize_database(staging)
        conn = connect(staging)
        conn.execute("BEGIN IMMEDIATE")

        # Parse CVE List V5 one JSON member at a time and retain the source record.
        cve_cwes = set()
        cve_source = "CVE List V5"
        cve_url = "https://github.com/CVEProject/cvelistV5"
        cve_sql = """INSERT OR REPLACE INTO cves
            (cve_id,title,description,cvss_score,severity,cve_state,date_published,date_updated,
             affected_json,references_json,metrics_json,problem_types_json,record_json,source_name,
             source_version,source_ref,imported_by)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
        cve_rows = []
        cve_json_count = 0
        with zipfile.ZipFile(args.cve_zip) as archive:
            for member in archive.infolist():
                if member.is_dir() or not member.filename.lower().endswith(".json"):
                    continue
                try:
                    record = json.loads(archive.read(member).decode("utf-8-sig"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(record, dict):
                    continue
                cve_json_count += 1
                if cve_json_count % 50000 == 0:
                    print("已检查 {} 个 CVE JSON 文件。".format(cve_json_count), flush=True)
                meta = record.get("cveMetadata", {})
                if not isinstance(meta, dict):
                    continue
                cve_id = str(meta.get("cveId", "")).upper()
                if not CVE_RE.match(cve_id):
                    continue
                containers = record.get("containers", {})
                if not isinstance(containers, dict):
                    continue
                cna = containers.get("cna", {}) or {}
                if not isinstance(cna, dict):
                    cna = {}
                adps = containers.get("adp", []) or []
                if not isinstance(adps, list):
                    adps = []
                adps = [item for item in adps if isinstance(item, dict)]
                all_containers = [cna] + adps
                description = _first_english(cna.get("descriptions", [])) or ""
                affected, references, problems = [], [], []
                for source in all_containers:
                    affected.extend(source.get("affected", []) or [])
                    references.extend(source.get("references", []) or [])
                    problems.extend(source.get("problemTypes", []) or [])
                for weakness_id in _cwe_ids(problems):
                    cve_cwes.add((cve_id, weakness_id))
                score, severity, metrics = _cvss(all_containers)
                cve_rows.append((cve_id, cna.get("title", "") or "", description, score, severity,
                    meta.get("state", "") or "", meta.get("datePublished", "") or "", meta.get("dateUpdated", "") or "",
                    _json(affected), _json(references), _json(metrics), _json(problems), _json(record),
                    cve_source, versions[cve_source], cve_url + "/blob/main/" + member.filename, "F2 offline build"))
                if len(cve_rows) >= 1000:
                    conn.executemany(cve_sql, cve_rows); cve_rows = []
                    conn.commit(); conn.execute("BEGIN IMMEDIATE")
            if cve_rows:
                conn.executemany(cve_sql, cve_rows)
        counts["cves"] = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        print("CVE 表已写入 {} 条记录。".format(counts["cves"]), flush=True)

        # CWE catalog and explicit CWE -> CAPEC links.
        with zipfile.ZipFile(args.cwe_zip) as archive:
            xml = ET.fromstring(archive.read(archive.namelist()[0]))
        cwe_version = xml.attrib.get("Version", versions["CWE"])
        cwe_rows, cwe_capec_rows = [], []
        for weakness in xml.findall(".//cwe:Weakness", NS):
            number = weakness.attrib.get("ID", "")
            if not number.isdigit():
                continue
            cwe_id = "CWE-" + number
            cwe_rows.append(_source_row((cwe_id, weakness.attrib.get("Name", ""), _text(weakness, "cwe:Description")),
                                        "CWE", cwe_version, "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip#" + cwe_id))
            for related in weakness.findall(".//cwe:Related_Attack_Pattern", NS):
                capec_id = related.attrib.get("CAPEC_ID", "")
                if capec_id.isdigit():
                    cwe_capec_rows.append(_source_row((cwe_id, "CAPEC-" + capec_id), "CWE", cwe_version,
                        "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip#" + cwe_id + "/CAPEC-" + capec_id))
        _insert_many(conn, "INSERT OR REPLACE INTO cwes(cwe_id,name,description,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?,?)", cwe_rows)
        counts["cwes"] = len(cwe_rows)
        print("CWE 表已写入 {} 条记录。".format(counts["cwes"]), flush=True)

        # CAPEC catalog and links to weaknesses.
        with zipfile.ZipFile(args.capec_zip) as archive:
            xml = ET.fromstring(archive.read(archive.namelist()[0]))
        capec_version = xml.attrib.get("Version", versions["CAPEC"])
        capec_rows, capec_cwe_rows = [], []
        for pattern in xml.findall(".//capec:Attack_Pattern", NS):
            number = pattern.attrib.get("ID", "")
            if not number.isdigit():
                continue
            capec_id = "CAPEC-" + number
            capec_rows.append(_source_row((capec_id, pattern.attrib.get("Name", ""), _text(pattern, "capec:Description")),
                "CAPEC", capec_version, "https://capec.mitre.org/data/xml/views/2000.xml.zip#" + capec_id))
            for weakness in pattern.findall(".//capec:Related_Weakness", NS):
                number_cwe = weakness.attrib.get("CWE_ID", "")
                if number_cwe.isdigit():
                    capec_cwe_rows.append(("CWE-" + number_cwe, capec_id))
        _insert_many(conn, "INSERT OR REPLACE INTO capecs(capec_id,name,description,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?,?)", capec_rows)
        counts["capecs"] = len(capec_rows)
        print("CAPEC 表已写入 {} 条记录。".format(counts["capecs"]), flush=True)
        for cwe_id, capec_id in capec_cwe_rows:
            cwe_capec_rows.append(_source_row((cwe_id, capec_id), "CAPEC", capec_version,
                "https://capec.mitre.org/data/xml/views/2000.xml.zip#" + capec_id + "/" + cwe_id))
        _insert_many(conn, "INSERT OR REPLACE INTO cwe_capec(cwe_id,capec_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)",
                     (row for row in cwe_capec_rows if conn.execute("SELECT 1 FROM cwes WHERE cwe_id=?", (row[0],)).fetchone()))

        # Parse ATT&CK STIX bundle into tactics, techniques, mitigations, and relations.
        with open(args.attack_json, "r", encoding="utf-8-sig") as stream:
            bundle = json.load(stream)
        objects = bundle.get("objects", [])
        tactic_by_short = {}
        tactics, techniques, technique_tactics, mitigations = [], [], [], []
        stix_to_attack, stix_to_mitigation = {}, {}
        attack_url = "https://github.com/mitre-attack/attack-stix-data/blob/v{}/enterprise-attack/enterprise-attack-{}.json".format(args.attack_version, args.attack_version)
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                tactic_id = _external_id(obj, "mitre-attack")
                short = obj.get("x_mitre_shortname", "")
                if re.match(r"^TA\d{4}$", tactic_id) and short:
                    tactic_by_short[short] = tactic_id
                    tactics.append(_source_row((tactic_id, short, obj.get("name", "") or "", obj.get("description", "") or ""),
                        "MITRE ATT&CK Enterprise", args.attack_version, attack_url + "#" + tactic_id))
        for obj in objects:
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            if obj.get("type") == "attack-pattern":
                attack_id = _external_id(obj, "mitre-attack")
                if not ATTACK_RE.match(attack_id):
                    continue
                phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) or []
                          if p.get("kill_chain_name") == "mitre-attack"]
                tactic_ids = sorted(set(tactic_by_short[p] for p in phases if p in tactic_by_short))
                techniques.append(_source_row((attack_id, obj.get("name", "") or "", obj.get("description", "") or "",
                    _json(tactic_ids), _json(obj.get("x_mitre_platforms", []) if isinstance(obj.get("x_mitre_platforms", []), list) else [])), "MITRE ATT&CK Enterprise",
                    args.attack_version, attack_url + "#" + attack_id))
                stix_to_attack[obj.get("id")] = attack_id
                for tactic_id in tactic_ids:
                    tactic = next((row for row in tactics if row[0] == tactic_id), None)
                    if tactic:
                        technique_tactics.append(_source_row((attack_id, tactic_id), "MITRE ATT&CK Enterprise",
                            args.attack_version, attack_url + "#" + attack_id + "/" + tactic[1]))
            elif obj.get("type") == "course-of-action":
                mitigation_id = _external_id(obj, "mitre-attack")
                if not re.match(r"^M\d{4}(?:\.\d{3})?$", mitigation_id):
                    continue
                mitigations.append(_source_row((mitigation_id, obj.get("name", "") or "", obj.get("description", "") or ""),
                    "MITRE ATT&CK Enterprise", args.attack_version, attack_url + "#" + mitigation_id))
                stix_to_mitigation[obj.get("id")] = mitigation_id
        _insert_many(conn, "INSERT OR REPLACE INTO tactics(tactic_id,short_name,name,description,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?,?,?)", tactics)
        _insert_many(conn, "INSERT OR REPLACE INTO techniques(attack_id,name,description,tactic_ids,platforms,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?,?,?,?)", techniques)
        _insert_many(conn, "INSERT OR REPLACE INTO technique_tactics(attack_id,tactic_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)", technique_tactics)
        _insert_many(conn, "INSERT OR REPLACE INTO mitigations(mitigation_id,name,description,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?,?)", mitigations)
        counts.update({"tactics": len(tactics), "techniques": len(techniques), "mitigations": len(mitigations)})
        print("ATT&CK 已写入 {} 个战术、{} 个技术和 {} 个缓解措施。".format(
            counts["tactics"], counts["techniques"], counts["mitigations"]), flush=True)

        relationships = []
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
                continue
            attack_id = stix_to_attack.get(obj.get("target_ref"))
            mitigation_id = stix_to_mitigation.get(obj.get("source_ref"))
            if attack_id and mitigation_id:
                relationships.append(_source_row((attack_id, mitigation_id), "MITRE ATT&CK Enterprise", args.attack_version,
                    attack_url + "#" + str(obj.get("id", ""))))
        _insert_many(conn, "INSERT OR REPLACE INTO technique_mitigations(attack_id,mitigation_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)", relationships)

        # CAPEC's official ATT&CK-related view encodes technique IDs in taxonomy mappings.
        capec_attack = []
        with zipfile.ZipFile(args.capec_attack_zip) as archive:
            csv_name = archive.namelist()[0]
            text = archive.read(csv_name).decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        for raw_row in reader:
            # Some CAPEC CSV mirrors wrap header names in literal apostrophes,
            # e.g. `'ID'` and `'Taxonomy Mappings'`. Normalize headers so both
            # the official CSV and these exported copies are handled.
            row = {str(key).strip("'\""): value for key, value in raw_row.items() if key is not None}
            capec_number = str(row.get("ID", "")).strip()
            mapping_text = row.get("Taxonomy Mappings", "") or ""
            if not capec_number.isdigit() or "ATTACK" not in mapping_text.upper():
                continue
            capec_id = "CAPEC-" + capec_number
            for match in CAPEC_ATTACK_RE.findall(mapping_text):
                attack_id = "T" + match
                capec_attack.append((capec_id, attack_id))
        capec_attack_rows = [_source_row(pair, "CAPEC ATT&CK Related Patterns", capec_version,
            "https://capec.mitre.org/data/csv/658.csv.zip#CAPEC-{}".format(pair[0].split("-")[1])) for pair in capec_attack]
        _insert_many(conn, "INSERT OR REPLACE INTO capec_attack(capec_id,attack_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)",
                     (row for row in capec_attack_rows if conn.execute("SELECT 1 FROM capecs WHERE capec_id=?", (row[0],)).fetchone()
                      and conn.execute("SELECT 1 FROM techniques WHERE attack_id=?", (row[1],)).fetchone()))
        counts["capec_attack"] = conn.execute("SELECT COUNT(*) FROM capec_attack").fetchone()[0]

        # Resolve CVE->CWE only after the CWE catalog has been loaded.
        _insert_many(conn, "INSERT OR REPLACE INTO cve_cwe(cve_id,cwe_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)",
            (_source_row(pair, "CVE List V5", args.cve_version, cve_url + "#" + pair[0])
             for pair in cve_cwes if conn.execute("SELECT 1 FROM cwes WHERE cwe_id=?", (pair[1],)).fetchone()))

        # CICAT candidates are checked against official CVE and Enterprise technique IDs.
        cicat_hash = hashes["cicat"]
        cicat_rows, cicat_seen, cicat_accepted, cicat_no_candidate = [], set(), set(), set()
        cicat_unusable, cicat_unknown_cves = set(), set()
        invalid_cicat_candidates = 0
        conn.execute("UPDATE cves SET cicat_validation_state='not_present',cicat_validation_note='CICAT 文件中未出现该 CVE'")
        with open(args.cicat_jsonl, "r", encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    outer = json.loads(line)
                except ValueError:
                    continue
                for cve_id, data in outer.items():
                    cve_id = str(cve_id).upper()
                    if not CVE_RE.match(cve_id) or not isinstance(data, dict):
                        continue
                    if not conn.execute("SELECT 1 FROM cves WHERE cve_id=?", (cve_id,)).fetchone():
                        cicat_unknown_cves.add(cve_id)
                        continue
                    cicat_seen.add(cve_id)
                    raw_techniques = data.get("TECHNIQUES", []) or []
                    if not isinstance(raw_techniques, list):
                        raw_techniques = []
                        cicat_unusable.add(cve_id)
                    for raw_attack_id in raw_techniques:
                        attack_id = str(raw_attack_id).strip().upper()
                        if attack_id.isdigit() or re.match(r"^\d{4}(?:\.\d{3})?$", attack_id):
                            attack_id = "T" + attack_id
                        if not ATTACK_RE.match(attack_id):
                            invalid_cicat_candidates += 1
                            cicat_unusable.add(cve_id)
                            continue
                        if conn.execute("SELECT 1 FROM techniques WHERE attack_id=?", (attack_id,)).fetchone():
                            cicat_accepted.add(cve_id)
                            cicat_rows.append((cve_id, attack_id, "CICAT", "sha256:" + cicat_hash,
                                args.cicat_jsonl + "#line:" + str(line_number), "F2 offline build"))
                            if len(cicat_rows) >= 1000:
                                conn.executemany("INSERT OR REPLACE INTO cve_attack_supplements(cve_id,attack_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)", cicat_rows)
                                cicat_rows = []
                                conn.commit(); conn.execute("BEGIN IMMEDIATE")
                        else:
                            invalid_cicat_candidates += 1
                            cicat_unusable.add(cve_id)
                    if not raw_techniques:
                        cicat_no_candidate.add(cve_id)
        if cicat_rows:
            conn.executemany("INSERT OR REPLACE INTO cve_attack_supplements(cve_id,attack_id,source_name,source_version,source_ref,imported_by) VALUES(?,?,?,?,?,?)", cicat_rows)
        for cve_id in cicat_no_candidate:
            conn.execute("UPDATE cves SET cicat_validation_state='no_candidate',cicat_validation_note='CICAT 有该 CVE 记录，但没有提供技战术候选' WHERE cve_id=?", (cve_id,))
        for cve_id in cicat_unusable.difference(cicat_accepted):
            conn.execute("UPDATE cves SET cicat_validation_state='unusable',cicat_validation_note='CICAT 候选中的技战术 ID 无法与当前 Enterprise ATT&CK 目录匹配' WHERE cve_id=?", (cve_id,))
        counts["cicat_candidates"] = conn.execute("SELECT COUNT(*) FROM cve_attack_supplements").fetchone()[0]
        counts["cicat_cves_present"] = len(cicat_seen)
        counts["cicat_unknown_cve_ids"] = len(cicat_unknown_cves)
        counts["cicat_invalid_candidates"] = invalid_cicat_candidates
        print("CICAT 校验与补充候选处理完成。", flush=True)

        conn.commit(); conn.execute("BEGIN IMMEDIATE")
        print("开始流式重建 CVE—ATT&CK 映射。", flush=True)
        rebuild_mappings(conn, commit_batches=True)
        source_summary = "|".join("{}:{}".format(name, digest) for name, digest in sorted(hashes.items()))
        package_hash = hashlib.sha256(source_summary.encode("utf-8")).hexdigest()
        package_id = "f2-initial-{}".format(hashes["cve"][:16])
        conn.execute("INSERT INTO package_imports(package_id,package_version,package_name,sha256,imported_by) VALUES(?,?,?,?,?)",
            (package_id, args.cve_version + "; ATT&CK " + args.attack_version, "F2 initial offline knowledge build", package_hash, "F2 offline build"))
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close(); conn = None
        os.replace(staging, args.db)
        counts["mappings"] = _count(args.db, "cve_attack_mappings")
        counts["mapping_states"] = _mapping_states(args.db)
        return counts
    except BaseException:
        if conn is not None:
            conn.rollback(); conn.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(staging + suffix)
            except OSError:
                pass
        raise


def _count(path, table):
    conn = connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
    finally:
        conn.close()


def _mapping_states(path):
    conn = connect(path)
    try:
        return {row[0]: row[1] for row in conn.execute("SELECT mapping_state,COUNT(*) FROM cves GROUP BY mapping_state")}
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-zip", required=True, help="CVE List V5 full baseline ZIP")
    parser.add_argument("--cve-version", required=True, help="CVE release tag, e.g. cve_2026-10-22_0000Z")
    parser.add_argument("--attack-json", required=True, help="ATT&CK Enterprise STIX bundle JSON")
    parser.add_argument("--attack-version", required=True, help="ATT&CK Enterprise release, e.g. 20.0")
    parser.add_argument("--cwe-zip", required=True, help="CWE XML ZIP")
    parser.add_argument("--capec-zip", required=True, help="CAPEC comprehensive XML ZIP")
    parser.add_argument("--capec-attack-zip", required=True, help="CAPEC ATT&CK Related Patterns CSV ZIP")
    parser.add_argument("--cicat-jsonl", required=True, help="CICAT cve2technique.jsonl")
    parser.add_argument("--db", required=True, help="New SQLite database output path")
    args = parser.parse_args()
    print(json.dumps(build(args), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
