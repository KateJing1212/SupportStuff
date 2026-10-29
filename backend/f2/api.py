"""HTTP API for the F2 offline knowledge base."""
from flask import Blueprint, current_app, jsonify, request
from werkzeug.exceptions import HTTPException
import sqlite3
import json

from .db import connect
from .exports import TABLES, export_table
from .packages import import_package
from .repository import cve_detail, mapping_rows, page_rows, rebuild_mappings, update_display_fields


api = Blueprint("f2", __name__)


def _error(code, message, status):
    return jsonify({"error": {"code": code, "message": str(message)}}), status


def _json_body():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")
    return payload


def _page_args():
    try:
        return int(request.args.get("page", 1)), int(request.args.get("page_size", 50))
    except ValueError:
        raise ValueError("page 和 page_size 必须为整数")


@api.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, ValueError):
        return _error("invalid_request", exc, 400)
    current_app.logger.exception("F2 API error")
    return _error("internal_error", "F2 服务处理请求时发生错误", 500)


@api.route("/health", methods=["GET"])
def health():
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        version = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
    finally:
        conn.close()
    return jsonify({"status": "ok", "module": "F2", "schema_version": int(version), "offline": True})


@api.route("/summary", methods=["GET"])
def summary():
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        counts = {}
        for table in ("cves", "cwes", "capecs", "tactics", "techniques", "mitigations", "cve_attack_mappings"):
            counts[table] = conn.execute("SELECT COUNT(*) FROM {}".format(table)).fetchone()[0]
        states = {row[0]: row[1] for row in conn.execute("SELECT mapping_state,COUNT(*) FROM cves GROUP BY mapping_state")}
        imports = [dict(row) for row in conn.execute("SELECT package_id,package_version,package_name,sha256,imported_by,imported_at FROM package_imports ORDER BY imported_at DESC")]
        return jsonify({"counts": counts, "mapping_states": states, "imports": imports})
    finally:
        conn.close()


@api.route("/cves", methods=["GET"])
def list_cves():
    page, size = _page_args()
    clauses, params = [], []
    query = request.args.get("q", "").strip()
    if query:
        clauses.append("(cve_id LIKE ? OR title LIKE ? OR description LIKE ?)")
        params.extend(["%" + query + "%"] * 3)
    state = request.args.get("mapping_state")
    if state:
        if state not in ("mapped", "partial", "unmapped"):
            raise ValueError("mapping_state 必须为 mapped、partial 或 unmapped")
        clauses.append("mapping_state=?"); params.append(state)
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        result = page_rows(
            conn, "cves", " AND ".join(clauses) if clauses else "1=1",
            params, page, size, "date_published DESC,cve_id DESC",
        )
        for item in result["items"]:
            _decode_cve(item)
        return jsonify(result)
    finally:
        conn.close()


@api.route("/cves/<cve_id>", methods=["GET", "PUT"])
def cve_item(cve_id):
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        if request.method == "GET":
            result = cve_detail(conn, cve_id.upper())
            if result:
                _decode_cve(result)
            return jsonify(result) if result else _error("not_found", "CVE 不存在", 404)
        payload = _json_body()
        forbidden = {"cve_id", "mapping_state", "mapping_note", "source_name", "source_version", "source_ref", "package_id", "imported_by"}
        if forbidden.intersection(payload):
            raise ValueError("CVE 标识、映射状态和来源只能由数据包/后端维护")
        for key in ("title", "description", "severity"):
            if key in payload and not isinstance(payload[key], str):
                raise ValueError("{} 必须是字符串".format(key))
        if "cvss_score" in payload and payload["cvss_score"] is not None:
            if not isinstance(payload["cvss_score"], (int, float)) or not 0 <= payload["cvss_score"] <= 10:
                raise ValueError("cvss_score 必须在 0 至 10 之间")
        if not update_display_fields(conn, "cves", "cve_id", cve_id.upper(), payload, ("title", "description", "cvss_score", "severity")):
            return _error("not_found", "CVE 不存在", 404)
        conn.commit()
        result = cve_detail(conn, cve_id.upper())
        _decode_cve(result)
        return jsonify(result)
    finally:
        conn.close()


@api.route("/techniques", methods=["GET"])
def list_techniques():
    page, size = _page_args()
    q = request.args.get("q", "").strip()
    where, params = ("(attack_id LIKE ? OR name LIKE ? OR description LIKE ?)", ["%" + q + "%"] * 3) if q else ("1=1", [])
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        result = page_rows(conn, "techniques", where, params, page, size, "attack_id")
        for item in result["items"]:
            item["tactic_ids"] = json.loads(item["tactic_ids"])
            item["platforms"] = json.loads(item["platforms"])
            item["tactics"] = _tactics_for(conn, item["attack_id"])
        return jsonify(result)
    finally:
        conn.close()


@api.route("/techniques/<attack_id>", methods=["GET", "PUT"])
def technique_item(attack_id):
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        if request.method == "GET":
            row = conn.execute("SELECT * FROM techniques WHERE attack_id=?", (attack_id.upper(),)).fetchone()
            if not row:
                return _error("not_found", "ATT&CK 技术不存在", 404)
            result = dict(row)
            result["tactic_ids"] = json.loads(result["tactic_ids"]); result["platforms"] = json.loads(result["platforms"])
            result["tactics"] = _tactics_for(conn, attack_id.upper())
            result["mitigations"] = [dict(x) for x in conn.execute("SELECT m.*,r.source_ref as relation_source_ref FROM technique_mitigations r JOIN mitigations m ON m.mitigation_id=r.mitigation_id WHERE r.attack_id=? ORDER BY m.mitigation_id", (attack_id.upper(),))]
            result["cves"] = [dict(x) for x in conn.execute("SELECT DISTINCT c.cve_id,c.title,c.mapping_state FROM cve_attack_mappings m JOIN cves c ON c.cve_id=m.cve_id WHERE m.attack_id=? AND m.mapping_state='mapped' ORDER BY c.cve_id", (attack_id.upper(),))]
            return jsonify(result)
        payload = _json_body()
        if set(payload).intersection({"attack_id", "tactic_ids", "platforms", "source_name", "source_version", "source_ref", "package_id", "imported_by"}):
            raise ValueError("技术标识、战术、平台及来源由离线数据包维护")
        if any(key in payload and not isinstance(payload[key], str) for key in ("name", "description")):
            raise ValueError("name 和 description 必须为字符串")
        if not update_display_fields(conn, "techniques", "attack_id", attack_id.upper(), payload, ("name", "description")):
            return _error("not_found", "ATT&CK 技术不存在", 404)
        conn.commit()
        return jsonify(dict(conn.execute("SELECT * FROM techniques WHERE attack_id=?", (attack_id.upper(),)).fetchone()))
    finally:
        conn.close()


@api.route("/mitigations", methods=["GET"])
def list_mitigations():
    page, size = _page_args(); q = request.args.get("q", "").strip()
    where, params = ("(mitigation_id LIKE ? OR name LIKE ? OR description LIKE ?)", ["%" + q + "%"] * 3) if q else ("1=1", [])
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        return jsonify(page_rows(conn, "mitigations", where, params, page, size, "mitigation_id"))
    finally:
        conn.close()


@api.route("/<catalog>", methods=["GET"])
def list_catalog(catalog):
    config = {
        "cwes": ("cwes", "cwe_id", ("cwe_id", "name", "description")),
        "capecs": ("capecs", "capec_id", ("capec_id", "name", "description")),
        "tactics": ("tactics", "tactic_id", ("tactic_id", "short_name", "name", "description")),
        "mitigations": ("mitigations", "mitigation_id", ("mitigation_id", "name", "description")),
    }
    if catalog not in config:
        return _error("not_found", "未知知识库目录", 404)
    table, key, fields = config[catalog]
    page, size = _page_args(); q = request.args.get("q", "").strip()
    where = "({} LIKE ? OR name LIKE ? OR description LIKE ?)".format(key) if q else "1=1"
    params = ["%" + q + "%"] * 3 if q else []
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        return jsonify(page_rows(conn, table, where, params, page, size, key))
    finally:
        conn.close()


@api.route("/<catalog>/<item_id>", methods=["GET", "PUT"])
def catalog_item(catalog, item_id):
    config = {
        "cwes": ("cwes", "cwe_id", ("name", "description")),
        "capecs": ("capecs", "capec_id", ("name", "description")),
        "tactics": ("tactics", "tactic_id", ("name", "description")),
        "mitigations": ("mitigations", "mitigation_id", ("name", "description")),
    }
    if catalog not in config:
        return _error("not_found", "未知知识库目录", 404)
    table, key, editable = config[catalog]
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        value = item_id.upper()
        if request.method == "GET":
            row = conn.execute("SELECT * FROM {} WHERE {}=?".format(table, key), (value,)).fetchone()
            return jsonify(dict(row)) if row else _error("not_found", "知识条目不存在", 404)
        payload = _json_body()
        if set(payload).difference(editable):
            raise ValueError("仅允许编辑名称和描述；标识及来源由离线数据包维护")
        if any(not isinstance(payload[field], str) for field in payload):
            raise ValueError("名称和描述必须为字符串")
        if not update_display_fields(conn, table, key, value, payload, editable):
            return _error("not_found", "知识条目不存在", 404)
        conn.commit()
        return jsonify(dict(conn.execute("SELECT * FROM {} WHERE {}=?".format(table, key), (value,)).fetchone()))
    finally:
        conn.close()


@api.route("/mappings", methods=["GET"])
def list_mappings():
    page, size = _page_args()
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        return jsonify(mapping_rows(conn, request.args.get("cve_id"), request.args.get("attack_id"), request.args.get("state"), page, size))
    finally:
        conn.close()


RELATION_TYPES = {
    "cve-cwe": ("cve_cwe", ("cve_id", "cwe_id")),
    "cwe-capec": ("cwe_capec", ("cwe_id", "capec_id")),
    "capec-attack": ("capec_attack", ("capec_id", "attack_id")),
    "technique-tactic": ("technique_tactics", ("attack_id", "tactic_id")),
    "technique-mitigation": ("technique_mitigations", ("attack_id", "mitigation_id")),
}


@api.route("/relationships/<relation_type>", methods=["GET", "POST", "DELETE"])
def relationships(relation_type):
    if relation_type not in RELATION_TYPES:
        return _error("not_found", "未知关系类型", 404)
    table, keys = RELATION_TYPES[relation_type]
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        if request.method == "GET":
            page, size = _page_args()
            clauses, params = [], []
            for query_key, field in (("left_id", keys[0]), ("right_id", keys[1])):
                value = request.args.get(query_key)
                if value:
                    clauses.append(field + "=?"); params.append(value.upper())
            return jsonify(page_rows(conn, table, " AND ".join(clauses) if clauses else "1=1", params, page, size, ",".join(keys)))
        payload = _json_body()
        if not all(payload.get(key) for key in keys):
            raise ValueError("关系记录缺少端点 ID")
        values = tuple(str(payload[key]).upper() for key in keys)
        if request.method == "DELETE":
            cursor = conn.execute("DELETE FROM {} WHERE {}=? AND {}=?".format(table, keys[0], keys[1]), values)
            if cursor.rowcount == 0:
                return _error("not_found", "关系记录不存在", 404)
        else:
            allowed = set(keys) | {"source_name", "source_version", "source_ref", "imported_by"}
            if set(payload).difference(allowed):
                raise ValueError("关系只接受端点 ID、来源名称/版本/引用和导入人")
            if not all(payload.get(field) for field in ("source_name", "source_version", "source_ref", "imported_by")):
                raise ValueError("关系记录必须包含来源名称、版本、引用和导入人")
            columns = ",".join(keys + ("source_name", "source_version", "source_ref", "imported_by"))
            marks = ",".join(["?"] * (len(keys) + 4))
            conn.execute("INSERT OR REPLACE INTO {}({}) VALUES({})".format(table, columns, marks), values + tuple(payload[field] for field in ("source_name", "source_version", "source_ref", "imported_by")))
        if relation_type in ("cve-cwe", "cwe-capec", "capec-attack"):
            rebuild_mappings(conn)
        conn.commit()
        if request.method == "DELETE":
            return jsonify({"deleted": True, "relation_type": relation_type, "ids": values})
        return jsonify({"relation_type": relation_type, "record": {key: value for key, value in zip(keys, values)},
                        "source_name": payload["source_name"], "source_version": payload["source_version"],
                        "source_ref": payload["source_ref"], "imported_by": payload["imported_by"]}), 201
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        return _error("invalid_reference", "关系端点不存在或约束不满足: {}".format(exc), 400)
    finally:
        conn.close()


@api.route("/f6/cve/<cve_id>/techniques", methods=["GET"])
def f6_techniques(cve_id):
    page, size = _page_args()
    conn = connect(current_app.config["F2_DB_PATH"])
    try:
        result = conn.execute("SELECT mapping_state,mapping_note FROM cves WHERE cve_id=?", (cve_id.upper(),)).fetchone()
        if not result:
            return _error("not_found", "CVE 不存在", 404)
        rows = mapping_rows(conn, cve_id.upper(), state="mapped", page=page, page_size=size)
        return jsonify({"cve_id": cve_id.upper(), "mapping_state": result["mapping_state"], "mapping_note": result["mapping_note"],
                        "mappings": rows["items"], "page": rows["page"], "page_size": rows["page_size"], "total": rows["total"]})
    finally:
        conn.close()


@api.route("/packages/import", methods=["POST"])
def package_import():
    upload = request.files.get("file")
    if upload is None:
        raise ValueError("multipart/form-data 中缺少 file")
    try:
        result = import_package(current_app.config["F2_DB_PATH"], upload.read())
    except ValueError as exc:
        return _error("invalid_package", exc, 400)
    return jsonify(result), 200 if result.get("unchanged") else 201


@api.route("/exports/<table>.<file_format>", methods=["GET"])
def export(table, file_format):
    if table not in TABLES:
        return _error("not_found", "不支持该导出表", 404)
    if file_format not in ("csv", "xlsx"):
        return _error("not_found", "仅支持 csv 或 xlsx", 404)
    try:
        return export_table(current_app.config["F2_DB_PATH"], table, file_format)
    except ValueError as exc:
        return _error("invalid_request", exc, 400)
    except RuntimeError as exc:
        return _error("dependency_missing", exc, 501)


def _decode_cve(item):
    for field in ("affected_json", "references_json", "metrics_json", "problem_types_json", "record_json"):
        value = item.pop(field, "{}" if field == "record_json" else "[]")
        try:
            item[field[:-5]] = json.loads(value)
        except (TypeError, ValueError):
            item[field[:-5]] = {} if field == "record_json" else []


def _tactics_for(conn, attack_id):
    return [dict(row) for row in conn.execute("""SELECT ta.tactic_id,ta.short_name,ta.name,r.source_name,r.source_version,r.source_ref
        FROM technique_tactics r JOIN tactics ta ON ta.tactic_id=r.tactic_id
        WHERE r.attack_id=? ORDER BY ta.tactic_id""", (attack_id,))]
