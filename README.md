# VibeScanner

VibeScanner is a Flask-based web vulnerability scanner with user accounts, live scan streaming, saved scan history, and exportable reports.

## Current Scope

- Reflected XSS detection
- Error-based, boolean-based, and time-based SQL injection detection
- Open Redirect detection for URL parameters and forms
- Form-based testing with per-field payload targeting
- Security header checks
- Sensitive file exposure checks
- Scan history, dashboard, and report exports

## Quick Start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the app:

```bash
python app.py
```

3. Open:

```text
http://127.0.0.1:5000
```

## Notes

- The app requires login before scanning.
- Scan targets are restricted to public `http` and `https` URLs.
- Set `VIBESCANNER_SECRET_KEY` before production use.
- Set `FLASK_DEBUG=1` only for local development.

## Project Layout

```text
VibeScanner/
|-- app.py
|-- db.py
|-- logger_config.py
|-- scanner.py
|-- requirements.txt
|-- ROADMAP.md
|-- run_accuracy_check.py
|-- test_vuln_app.py
|-- templates/
|   |-- dashboard.html
|   |-- index.html
|   |-- login.html
|   |-- scan_history.html
|   `-- signup.html
|-- instance/
|   `-- vibescanner.db
`-- logs/
```

## Reports and History

- `/history` shows saved scans and exports
- `/dashboard` shows aggregate statistics
- `/download_pdf?scan_id=<id>` exports PDF
- `/api/scan/<id>/export?format=json|csv|html` exports machine-readable reports

## Local Accuracy Check

Use the included local intentionally vulnerable app and regression harness:

```bash
python run_accuracy_check.py
```

That verifies the main scanner paths against known XSS and SQLi targets.
