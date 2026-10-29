
import os
import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, request, jsonify, render_template_string,
    send_file
)
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "fris.db"

MAX_FILE_SIZE = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".bin", ".img", ".rom", ".fw", ".hex", ".elf"}

for folder in (DATA_DIR, UPLOAD_DIR, REPORT_DIR):
    folder.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                event TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def assess_firmware(data):
    findings = []
    score = 0

    # These are preliminary byte-pattern checks, not full
    # firmware analysis or confirmed vulnerability detection.
    patterns = [
        (b"BEGIN RSA PRIVATE KEY", "Private-key marker found", 35),
        (b"password=", "Possible hard-coded password string", 25),
        (b"admin:admin", "Common default credential string", 25),
        (b"telnet", "Telnet-related string found", 10),
        (b"debug", "Debug-related string found", 5),
    ]

    lower_data = data.lower()

    for pattern, description, points in patterns:
        if pattern.lower() in lower_data:
            findings.append(description)
            score += points

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    if not findings:
        findings.append(
            "No configured byte-pattern indicators found. "
            "This does not prove the firmware is safe."
        )

    return score, level, findings


def make_audit_hash(scan_id, sha256, event, created_at):
    record = {
        "scan_id": scan_id,
        "firmware_sha256": sha256,
        "event": event,
        "created_at": created_at,
    }
    canonical = json.dumps(
        record, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@app.get("/")
def home():
    return jsonify({
        "project": "FRIS — Firmware Risk Intelligence System",
        "title": "Powered by Blockchain and AI Agents",
        "status": "Backend running",
        "endpoints": [
            "GET /api/health",
            "POST /api/scan",
            "GET /api/scans",
            "GET /api/scans/<id>",
            "GET /api/audit",
            "GET /api/reports/<id>"
        ]
    })


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "database": "SQLite",
        "analysis": "Preliminary byte-pattern checks only",
        "ai_agent": "Not connected yet",
        "blockchain": "Not connected; local audit hashes only"
    })


@app.post("/api/scan")
def scan_firmware():
    uploaded = request.files.get("firmware")

    if uploaded is None or not uploaded.filename:
        return jsonify({
            "error": "Choose a firmware file using the 'firmware' field."
        }), 400

    original_name = secure_filename(uploaded.filename)
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        return jsonify({
            "error": "Unsupported extension. Allowed: "
                     + ", ".join(sorted(ALLOWED_EXTENSIONS))
        }), 400

    data = uploaded.read(MAX_FILE_SIZE + 1)

    if len(data) > MAX_FILE_SIZE:
        return jsonify({"error": "File exceeds the 25 MB limit."}), 413

    if not data:
        return jsonify({"error": "The uploaded file is empty."}), 400

    firmware_hash = hashlib.sha256(data).hexdigest()
    score, level, findings = assess_firmware(data)
    created_at = datetime.now(timezone.utc).isoformat()

    # Store under a generated name, never the supplied filename.
    stored_name = f"{firmware_hash}{extension}"
    stored_path = UPLOAD_DIR / stored_name
    stored_path.write_bytes(data)

    with connect_db() as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (filename, sha256, size_bytes, risk_score,
             risk_level, findings, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            original_name, firmware_hash, len(data), score,
            level, json.dumps(findings), created_at
        ))
        scan_id = cursor.lastrowid

        event = "Firmware uploaded and preliminary assessment completed"
        audit_hash = make_audit_hash(
            scan_id, firmware_hash, event, created_at
        )
        conn.execute("""
            INSERT INTO audit_events
            (scan_id, event, record_hash, created_at)
            VALUES (?, ?, ?, ?)
        """, (scan_id, event, audit_hash, created_at))

    report = {
        "project": "FRIS",
        "scan_id": scan_id,
        "filename": original_name,
        "sha256": firmware_hash,
        "size_bytes": len(data),
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "created_at": created_at,
        "limitations": [
            "Preliminary byte-pattern checks only.",
            "No confirmed CVE matching is performed.",
            "No AI agent or public blockchain is connected.",
            "A low score does not prove firmware is safe."
        ]
    }

    report_path = REPORT_DIR / f"scan-{scan_id}.json"
    report_path.write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    return jsonify(report), 201


@app.get("/api/scans")
def list_scans():
    with connect_db() as conn:
        rows = conn.execute("""
            SELECT id, filename, sha256, size_bytes,
                   risk_score, risk_level, created_at
            FROM scans ORDER BY id DESC LIMIT 100
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.get("/api/scans/<int:scan_id>")
def get_scan(scan_id):
    with connect_db() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

    if row is None:
        return jsonify({"error": "Scan not found"}), 404

    result = dict(row)
    result["findings"] = json.loads(result["findings"])
    return jsonify(result)


@app.get("/api/audit")
def audit_log():
    with connect_db() as conn:
        rows = conn.execute("""
            SELECT id, scan_id, event, record_hash, created_at
            FROM audit_events ORDER BY id DESC LIMIT 100
        """).fetchall()

    return jsonify({
        "notice": "Local SQLite audit hashes; not a blockchain.",
        "events": [dict(row) for row in rows]
    })


@app.get("/api/reports/<int:scan_id>")
def download_report(scan_id):
    path = REPORT_DIR / f"scan-{scan_id}.json"

    if not path.is_file():
        return jsonify({"error": "Report not found"}), 404

    return send_file(
        path,
        as_attachment=True,
        download_name=f"FRIS-report-{scan_id}.json",
        mimetype="application/json"
    )


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({"error": "Maximum upload size is 25 MB."}), 413


init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
