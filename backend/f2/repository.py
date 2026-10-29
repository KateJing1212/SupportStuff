"""Knowledge base queries and evidence-chain mapping construction."""
import hashlib
import json


def rebuild_mappings(conn, commit_batches=False, batch_size=10000):
    conn.execute("DELETE FROM cve_attack_mappings")
    conn.execute("UPDATE cves SET mapping_state='unmapped',mapping_note='没有已提供的 CVE→CWE 分类关系',updated_at=CURRENT_TIMESTAMP")
    rows = conn.execute("""
        SELECT cc.cve_id,cc.cwe_id,cc.source_name csn,cc.source_version csv,cc.source_ref csr,cc.imported_by ci,
               wc.capec_id,wc.source_name wsn,wc.source_version wsv,wc.source_ref wsr,wc.imported_by wi,
               ca.attack_id,ca.source_name asn,ca.source_version asv,ca.source_ref asr,ca.imported_by ai,
               c.source_name cn,c.source_version cv,c.source_ref cr,c.imported_by cby,
               w.source_name wn,w.source_version wv,w.source_ref wr,w.imported_by wby,
               p.source_name pn,p.source_version pv,p.source_ref pr,p.imported_by pby,
               t.source_name tn,t.source_version tv,t.source_ref tr,t.imported_by tby
        FROM cve_cwe cc JOIN cwe_capec wc ON wc.cwe_id=cc.cwe_id
        JOIN capec_attack ca ON ca.capec_id=wc.capec_id
        JOIN cves c ON c.cve_id=cc.cve_id JOIN cwes w ON w.cwe_id=cc.cwe_id
        JOIN capecs p ON p.capec_id=wc.capec_id JOIN techniques t ON t.attack_id=ca.attack_id
        ORDER BY cc.cve_id,cc.cwe_id,wc.capec_id,ca.attack_id
    """)
    processed = 0
    for row in rows:
        processed += 1
        path = [row["cve_id"], row["cwe_id"], row["capec_id"], row["attack_id"]]
        mapping_id = hashlib.sha256("|".join(path).encode("utf-8")).hexdigest()
        refs = [row[k] for k in ("cr", "csr", "wr", "wsr", "pr", "asr", "tr")]
        versions = ["{} {}".format(row[k], row[v]) for k, v in (("cn", "cv"), ("csn", "csv"), ("wn", "wv"), ("wsn", "wsv"),
                    ("pn", "pv"), ("asn", "asv"), ("tn", "tv"))]
        imported_by = ", ".join(sorted(set(x for x in (row["cby"], row["ci"], row["wby"], row["wi"], row["pby"], row["ai"], row["tby"]) if x)))
        conn.execute("""INSERT OR REPLACE INTO cve_attack_mappings
            (mapping_id,cve_id,cwe_id,capec_id,attack_id,mapping_method,mapping_state,evidence_json,source_versions_json,source_refs_json,imported_by)
            VALUES(?,?,?,?,?,'derived_cwe_capec_attack_chain','mapped',?,?,?,?)""",
            (mapping_id, row["cve_id"], row["cwe_id"], row["capec_id"], row["attack_id"],
             json.dumps(path, ensure_ascii=False), json.dumps(versions, ensure_ascii=False), json.dumps(refs, ensure_ascii=False), imported_by))
        if commit_batches and processed % batch_size == 0:
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
    conn.execute("""UPDATE cves SET mapping_state='mapped',mapping_note='',updated_at=CURRENT_TIMESTAMP
        WHERE EXISTS (SELECT 1 FROM cve_attack_mappings m WHERE m.cve_id=cves.cve_id
            AND m.mapping_method='derived_cwe_capec_attack_chain')""")

    # Keep all validated CICAT candidates for comparison, but only let them
    # create an edge when no source-chain mapping already covers that pair.
    cicat_rows = conn.execute("""
        SELECT s.cve_id,s.attack_id,s.source_name,s.source_version,s.source_ref,s.imported_by
        FROM cve_attack_supplements s
        JOIN cves c ON c.cve_id=s.cve_id
        JOIN techniques t ON t.attack_id=s.attack_id
        ORDER BY s.cve_id,s.attack_id
    """)
    cicat_by_cve = {}
    official_by_cve = {}
    for row in conn.execute("SELECT cve_id,attack_id FROM cve_attack_mappings WHERE mapping_method='derived_cwe_capec_attack_chain'"):
        official_by_cve.setdefault(row["cve_id"], set()).add(row["attack_id"])
    cicat_processed = 0
    for row in cicat_rows:
        cicat_processed += 1
        cicat_by_cve.setdefault(row["cve_id"], set()).add(row["attack_id"])
        if row["attack_id"] in official_by_cve.get(row["cve_id"], set()):
            continue
        mapping_id = hashlib.sha256("{}|CICAT|{}".format(row["cve_id"], row["attack_id"]).encode("utf-8")).hexdigest()
        conn.execute("""INSERT OR REPLACE INTO cve_attack_mappings
            (mapping_id,cve_id,cwe_id,capec_id,attack_id,mapping_method,mapping_state,evidence_json,source_versions_json,source_refs_json,imported_by)
            VALUES(?,?,NULL,NULL,?,'cicat_supplement','mapped',?,?,?,?)""",
            (mapping_id, row["cve_id"], row["attack_id"],
             json.dumps(["CICAT direct CVE-to-ATT&CK candidate"], ensure_ascii=False),
             json.dumps(["{} {}".format(row["source_name"], row["source_version"])], ensure_ascii=False),
             json.dumps([row["source_ref"]], ensure_ascii=False), row["imported_by"]))
        conn.execute("UPDATE cves SET mapping_state='mapped',mapping_note='由 CICAT 补充直接映射；来源已逐条标注',updated_at=CURRENT_TIMESTAMP WHERE cve_id=? AND mapping_state!='mapped'", (row["cve_id"],))
        if commit_batches and cicat_processed % batch_size == 0:
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")

    for cve_id, cicat_ids in cicat_by_cve.items():
        official_ids = official_by_cve.get(cve_id, set())
        overlap = cicat_ids.intersection(official_ids)
        if not official_ids:
            state, note = "supplemented", "CICAT 提供 {} 条有效候选；无官方链映射，已作为补充映射".format(len(cicat_ids))
        elif overlap == cicat_ids:
            state, note = "agree", "CICAT {} 条有效候选均与来源链映射一致".format(len(cicat_ids))
        elif overlap:
            state, note = "partial_agreement", "CICAT {} 条候选中 {} 条与来源链映射一致".format(len(cicat_ids), len(overlap))
        else:
            state, note = "conflict", "CICAT 候选与来源链映射无交集；候选仅作缺失项补充并保留来源标记"
        conn.execute("UPDATE cves SET cicat_validation_state=?,cicat_validation_note=? WHERE cve_id=?", (state, note, cve_id))

    partial = conn.execute("""
       SELECT DISTINCT cc.cve_id FROM cve_cwe cc
       WHERE NOT EXISTS (SELECT 1 FROM cve_attack_mappings m WHERE m.cve_id=cc.cve_id)
    """)
    for row in partial:
        conn.execute("UPDATE cves SET mapping_state='partial',mapping_note='已有 CVE→CWE 关系，但缺少完整 CWE→CAPEC→ATT&CK 链',updated_at=CURRENT_TIMESTAMP WHERE cve_id=?", (row["cve_id"],))


def page_rows(conn, table, where="1=1", params=(), page=1, page_size=50, order="1"):
    page = max(1, int(page))
    page_size = min(500, max(1, int(page_size)))
    total = conn.execute("SELECT COUNT(*) FROM {} WHERE {}".format(table, where), params).fetchone()[0]
    items = conn.execute("SELECT * FROM {} WHERE {} ORDER BY {} LIMIT ? OFFSET ?".format(table, where, order),
                         tuple(params) + (page_size, (page - 1) * page_size)).fetchall()
    return {"items": [dict(row) for row in items], "page": page, "page_size": page_size, "total": total}


def cve_detail(conn, cve_id):
    cve = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
    if cve is None:
        return None
    result = dict(cve)
    result["cwes"] = [dict(row) for row in conn.execute("SELECT w.*,r.source_ref as relation_source_ref FROM cve_cwe r JOIN cwes w ON w.cwe_id=r.cwe_id WHERE r.cve_id=? ORDER BY w.cwe_id", (cve_id,))]
    result["mappings"] = mapping_rows(conn, cve_id=cve_id)
    return result


def mapping_rows(conn, cve_id=None, attack_id=None, state=None, page=1, page_size=50):
    clauses, params = [], []
    if cve_id:
        clauses.append("m.cve_id=?"); params.append(cve_id)
    if attack_id:
        clauses.append("m.attack_id=?"); params.append(attack_id)
    if state:
        clauses.append("m.mapping_state=?"); params.append(state)
    where = " AND ".join(clauses) if clauses else "1=1"
    page = max(1, int(page)); page_size = min(500, max(1, int(page_size)))
    total = conn.execute("SELECT COUNT(*) FROM cve_attack_mappings m WHERE " + where, params).fetchone()[0]
    rows = conn.execute("""SELECT m.*,t.name as technique_name FROM cve_attack_mappings m
        LEFT JOIN techniques t ON t.attack_id=m.attack_id WHERE {} ORDER BY m.cve_id,m.attack_id,m.cwe_id,m.capec_id LIMIT ? OFFSET ?""".format(where),
        tuple(params) + (page_size, (page - 1) * page_size)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["evidence_path"] = json.loads(item["evidence_json"])
        item["source_versions"] = json.loads(item["source_versions_json"])
        item["source_refs"] = json.loads(item["source_refs_json"])
        items.append(item)
    return {"items": items, "page": page, "page_size": page_size, "total": total}


def update_display_fields(conn, table, key, value, payload, allowed):
    row = conn.execute("SELECT 1 FROM {} WHERE {}=?".format(table, key), (value,)).fetchone()
    if not row:
        return False
    fields = [field for field in allowed if field in payload]
    if not fields:
        raise ValueError("请求中没有可编辑字段")
    assignments = ",".join("{}=?".format(field) for field in fields)
    params = [payload[field] for field in fields]
    conn.execute("UPDATE {} SET {} WHERE {}=?".format(table, assignments, key), tuple(params) + (value,))
    return True
