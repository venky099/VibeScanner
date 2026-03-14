import json
import threading
import time

from werkzeug.serving import make_server

from scanner import VulnerabilityScanner
from test_vuln_app import app as test_app


class ServerThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=5001):
        super().__init__(daemon=True)
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()
        self.ctx.pop()


def main():
    server = ServerThread(test_app)
    server.start()
    time.sleep(0.5)

    findings = []
    try:
        scanner = VulnerabilityScanner("http://127.0.0.1:5001/")
        for update in scanner.run_scan():
            if "[VULN]" not in update:
                continue
            payload = update.split("[VULN] ", 1)[1].strip()
            if payload.startswith("data: "):
                payload = payload[6:]
            findings.append(json.loads(payload))
    finally:
        server.shutdown()

    checks = {
        "reflected_xss": any(v.get("type") == "XSS (URL Parameter)" and "/xss" in v.get("url", "") for v in findings),
        "error_sqli": any(v.get("detection_method") == "error-based" and "/sqli" in v.get("url", "") for v in findings),
        "boolean_sqli": any(v.get("detection_method") == "boolean-based" and "/sqli_bool" in v.get("url", "") for v in findings),
        "time_sqli_url": any(v.get("detection_method") == "time-based" and "/sqli_time" in v.get("url", "") for v in findings),
        "form_sqli": any(v.get("type") == "SQL Injection (Form)" for v in findings),
        "open_redirect_url": any(v.get("type") == "Open Redirect (URL Parameter)" and "/redirect" in v.get("url", "") for v in findings),
        "open_redirect_form": any(v.get("type") == "Open Redirect (Form)" and "/forms" in v.get("url", "") for v in findings),
        "time_sqli_form": any(
            v.get("type") == "SQL Injection (Form)"
            and v.get("detection_method") == "time-based"
            and "[username]" in v.get("payload", "")
            for v in findings
        ),
    }

    print(json.dumps(findings, indent=2))
    print(json.dumps({"checks": checks}, indent=2))

    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"Accuracy check failed: missing expectations for {', '.join(failed)}")


if __name__ == "__main__":
    main()
