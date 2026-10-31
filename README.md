# PROJECT-Ransomware-

**Enterprise Ransomware Outbreak & Containment Architecture** is a local Flask-based incident response workbench for an academic threat intelligence and incident response demonstration. It uses a fictional enterprise scenario and synthetic evidence; it does not monitor or respond to real systems.

## Features

- SOC overview with incident metrics, severity and activity charts, and simulated alerts.
- Incident list and detail pages with affected hosts, severity, status, response notes, and MITRE ATT&CK technique IDs.
- Evidence lab for JSON, CSV, TXT, and LOG files (up to 5 MB) with SHA-256 calculation, basic IOC pattern matching, suspicious keyword checks, and timeline extraction.
- Synthetic evidence pack generator and downloads.
- Downloadable investigation reports.

Uploaded evidence is treated as data only. The application does not execute uploaded scripts or binaries. Analysis is based on basic patterns and is not a substitute for professional forensic tooling.

## Requirements

- Python 3
- pip

## Run locally

### Linux or macOS

```bash
cd "/home/reaper/project ramsomeware"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

### Windows PowerShell

```powershell
cd "C:\path\to\project ramsomeware"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in a browser. Stop the development server with `Ctrl+C`.

Chart.js is loaded from a CDN, so the charts require an internet connection. The rest of the app runs locally.

## Using the workbench

1. Review the simulated incident metrics on the SOC Overview page.
2. Open **Incident Management** to inspect incident records and details.
3. Use **Evidence Lab** to download synthetic artifacts or upload a supported evidence file.
4. Review the calculated hash, IOC matches, suspicious patterns, and extracted timeline.
5. Open **Investigation Report** or download a report from the Evidence Lab.

Use **Generate Evidence** to recreate the synthetic JSON evidence files in `generated/`.

## Project layout

```text
app.py                 Flask routes, scenario data, and evidence analysis
requirements.txt       Python dependencies
templates/             Jinja2 pages
static/css/            Dashboard styles
static/js/             Chart setup
generated/             Synthetic JSON evidence pack
uploads/               Local uploaded evidence (excluded from Git)
```

## Safety note

This is an educational demo, not a production incident response platform. Run it only on a trusted local machine. The built-in Flask development server has debug mode enabled, and the demo uses a hard-coded session key; do not expose it to an untrusted network or use it to process confidential evidence.
