"""CSV and XLSX exports for knowledge base tables."""
import csv
import io
import json

from flask import Response, stream_with_context

from .db import connect


TABLES = {
    "cves": "SELECT * FROM cves ORDER BY date_published DESC,cve_id DESC",
    "cwes": "SELECT * FROM cwes ORDER BY cwe_id",
    "capecs": "SELECT * FROM capecs ORDER BY capec_id",
    "tactics": "SELECT * FROM tactics ORDER BY tactic_id",
    "techniques": "SELECT * FROM techniques ORDER BY attack_id",
    "mitigations": "SELECT * FROM mitigations ORDER BY mitigation_id",
    "mappings": "SELECT * FROM cve_attack_mappings ORDER BY cve_id,attack_id,cwe_id,capec_id",
    "cve_attack_supplements": "SELECT * FROM cve_attack_supplements ORDER BY cve_id,attack_id",
    "cve_cwe": "SELECT * FROM cve_cwe ORDER BY cve_id,cwe_id",
    "cwe_capec": "SELECT * FROM cwe_capec ORDER BY cwe_id,capec_id",
    "capec_attack": "SELECT * FROM capec_attack ORDER BY capec_id,attack_id",
    "technique_tactics": "SELECT * FROM technique_tactics ORDER BY attack_id,tactic_id",
    "technique_mitigations": "SELECT * FROM technique_mitigations ORDER BY attack_id,mitigation_id",
}


def export_table(db_path, table, file_format):
    if table not in TABLES:
        raise ValueError("不支持导出的表：{}".format(table))
    conn = connect(db_path)
    cursor = conn.execute(TABLES[table])
    headers = [item[0] for item in cursor.description]
    if file_format == "csv":
        def generate_csv():
            stream = io.StringIO()
            writer = csv.writer(stream)
            try:
                writer.writerow(headers)
                yield "\ufeff" + stream.getvalue()
                stream.seek(0); stream.truncate(0)
                while True:
                    rows = cursor.fetchmany(500)
                    if not rows:
                        break
                    for row in rows:
                        writer.writerow([row[key] for key in headers])
                    yield stream.getvalue()
                    stream.seek(0); stream.truncate(0)
            finally:
                conn.close()

        return Response(stream_with_context(generate_csv()), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename={}.csv".format(table)})
    try:
        from openpyxl import Workbook
    except ImportError:
        conn.close()
        raise RuntimeError("XLSX 导出需要安装 openpyxl；CSV 导出无需额外依赖")
    try:
        book = Workbook(write_only=True)
        sheet = book.create_sheet(table)
        sheet.append(list(headers))
        for row in cursor:
            values = []
            for key in headers:
                value = row[key]
                if isinstance(value, str) and value.startswith(("[", "{")):
                    try:
                        value = json.dumps(json.loads(value), ensure_ascii=False)
                    except ValueError:
                        pass
                values.append(value)
            sheet.append(values)
        output = io.BytesIO()
        book.save(output)
        return Response(output.getvalue(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": "attachment; filename={}.xlsx".format(table)})
    finally:
        conn.close()
