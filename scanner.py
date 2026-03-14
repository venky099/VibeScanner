import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import json
import re
import traceback
import time
import urllib3
from difflib import SequenceMatcher
from logger_config import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_logger(__name__)

SQLI_ERROR_PATTERNS = {
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysqli_result",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "pg_numrows",
    "unterminated quoted string",
    "invalid input syntax for",
    "pgsql error",
    "postgresql error",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "unrecognized token",
    "unable to prepare statement",
    "sqlite3::query",
    # Oracle
    "ora-00933",
    "ora-00936",
    "ora-01756",
    "ora-00921",
    "ora-01747",
    "oracle error",
    "oracle driver",
    "quoted string not properly terminated",
    # SQL Server / MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark",
    "mssql_query",
    "odbc sql server driver",
    "sql server driver",
    "sqlsrv_query",
    "[microsoft][odbc",
    "[sqlserver]",
    # Generic SQL errors
    "sql syntax",
    "syntax error",
    "database error",
    "sql error",
    "warning: odbc",
    "invalid query",
    "sql command not properly ended",
    "unexpected end of sql command",
    "db2_execute",
    "sybase error",
    "interbase error",
    "dynamic sql error"
}

SQLI_ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "OR 1=1", "' OR '1", "1' ORDER BY 1,2,3--+", "-1 UNION SELECT 1 INTO @,@,@"]
SQLI_BOOLEAN_TEMPLATES = [
    {
        "label": "numeric boolean comparison",
        "true": "{base} AND 1=1",
        "false": "{base} AND 1=2"
    },
    {
        "label": "quoted boolean comparison",
        "true": "{base}' AND '1'='1",
        "false": "{base}' AND '1'='2"
    },
    {
        "label": "quoted OR boolean comparison",
        "true": "{base}' OR '1'='1",
        "false": "{base}' OR '1'='2"
    }
]
SQLI_TIME_DELAY_SECONDS = 3
SQLI_TIME_THRESHOLD_SECONDS = 2.2
SQLI_TIME_CONTROL_TOLERANCE_SECONDS = 1.0
SQLI_TIME_REQUEST_TIMEOUT_SECONDS = SQLI_TIME_DELAY_SECONDS + 5
SQLI_TIME_TEMPLATES = [
    {
        "label": "mysql sleep",
        "delay": "{base} AND SLEEP(3)",
        "control": "{base} AND SLEEP(0)"
    },
    {
        "label": "quoted mysql sleep",
        "delay": "{base}' AND SLEEP(3)-- ",
        "control": "{base}' AND SLEEP(0)-- "
    },
    {
        "label": "postgres sleep",
        "delay": "{base}; SELECT pg_sleep(3)",
        "control": "{base}; SELECT pg_sleep(0)"
    },
    {
        "label": "mssql waitfor",
        "delay": "{base}'; WAITFOR DELAY '0:0:3'--",
        "control": "{base}'; WAITFOR DELAY '0:0:0'--"
    }
]

XSS_DANGEROUS_TAGS = {"script", "img", "svg", "iframe", "body", "input"}
XSS_DANGEROUS_ATTRS = {"src", "href", "srcdoc", "action", "formaction"}
PASSIVE_HARDENING_METHOD = "passive-hardening"
PASSIVE_HARDENING_CONFIDENCE = "Advisory"

# CVSS-Based Vulnerability Scoring System
# Based on CVSS v3.1 (Common Vulnerability Scoring System)
CVSS_SCORES = {
    # SQL Injection Vulnerabilities
    "SQL Injection (URL Parameter)": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality, Integrity, Availability)",
        "description": "Allows attacker to read, modify, or delete database contents"
    },
    "SQL Injection (Form)": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality, Integrity, Availability)",
        "description": "Allows attacker to read, modify, or delete database contents via form input"
    },
    
    # LFI Vulnerabilities
    "Local File Inclusion (URL Parameter)": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Allows attacker to read local files on the server via URL parameter"
    },
    "Local File Inclusion (Form)": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Allows attacker to read local files on the server via form input"
    },
    
    # XSS Vulnerabilities
    "XSS (URL Parameter)": {
        "base_score": 6.1,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Confidentiality, Integrity)",
        "description": "Allows attacker to execute scripts in victim's browser via URL"
    },
    "XSS (Form)": {
        "base_score": 6.1,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Confidentiality, Integrity)",
        "description": "Allows attacker to execute scripts in victim's browser via form input"
    },
    
    # Security Header Vulnerabilities
    "Missing Security Header: X-Frame-Options": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Integrity)",
        "description": "Clickjacking protection is weaker because framing restrictions are not explicitly defined"
    },
    "Missing Security Header: Content-Security-Policy": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Integrity)",
        "description": "Defense-in-depth against script injection is weaker because no Content-Security-Policy is present"
    },
    "Missing Security Header: Strict-Transport-Security": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "HTTPS downgrade protection is weaker because HSTS is missing or ineffective"
    },
    "Missing Security Header: X-Content-Type-Options": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Integrity)",
        "description": "Browser may execute malicious files via MIME sniffing"
    },
    "Missing Security Header: Referrer-Policy": {
        "base_score": 0.0,
        "severity": "Info",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Confidentiality)",
        "description": "Referrer information may leak to third parties"
    },
    "Missing Security Header: Permissions-Policy": {
        "base_score": 0.0,
        "severity": "Info",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Confidentiality)",
        "description": "Browser features not restricted"
    },
    
    # Sensitive File Exposure - Critical
    "Sensitive File Exposure: /.git/": {
        "base_score": 9.1,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Complete source code and commit history exposed"
    },
    "Sensitive File Exposure: /.git/config": {
        "base_score": 9.1,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Git configuration with potential credentials exposed"
    },
    "Sensitive File Exposure: /.env": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality, Integrity, Availability)",
        "description": "Environment file with database passwords and API keys exposed"
    },
    "Sensitive File Exposure: /backup.sql": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Entire database backup downloadable"
    },
    "Sensitive File Exposure: /database.sql": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Database file downloadable"
    },
    "Sensitive File Exposure: /db.sql": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Database file downloadable"
    },
    "Sensitive File Exposure: /dump.sql": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Database dump downloadable"
    },
    "Sensitive File Exposure: /id_rsa": {
        "base_score": 9.8,
        "severity": "Critical",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality, Integrity, Availability)",
        "description": "Private SSH key exposed - full server compromise possible"
    },
    
    # Sensitive File Exposure - High
    "Sensitive File Exposure: /config.php": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "PHP config with database credentials exposed"
    },
    "Sensitive File Exposure: /wp-config.php": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "WordPress config with database credentials exposed"
    },
    "Sensitive File Exposure: /.htpasswd": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Password hashes exposed"
    },
    "Sensitive File Exposure: /web.config": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "IIS configuration with potential credentials exposed"
    },
    "Sensitive File Exposure: /.svn/": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "SVN repository with source code exposed"
    },
    "Sensitive File Exposure: /.bash_history": {
        "base_score": 7.5,
        "severity": "High",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Command history with potential credentials exposed"
    },
    
    # Sensitive File Exposure - Medium
    "Sensitive File Exposure: /.htaccess": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Server configuration rules exposed"
    },
    "Sensitive File Exposure: /phpinfo.php": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Server configuration and paths exposed"
    },
    "Sensitive File Exposure: /info.php": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Server configuration and paths exposed"
    },
    "Sensitive File Exposure: /server-status": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Apache server status and internal info exposed"
    },
    "Sensitive File Exposure: /error_log": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Error log with debugging info exposed"
    },
    "Sensitive File Exposure: /debug.log": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Debug log with sensitive info exposed"
    },
    
    # Sensitive File Exposure - Low
    "Sensitive File Exposure: /.DS_Store": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Directory structure exposed"
    },
    "Sensitive File Exposure: /crossdomain.xml": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Flash cross-domain policy found"
    },
    "Sensitive File Exposure: /clientaccesspolicy.xml": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Silverlight access policy found"
    },
    "Sensitive File Exposure: /id_rsa.pub": {
        "base_score": 2.4,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "None",
        "description": "Public SSH key exposed"
    },
    "Sensitive File Exposure: /composer.json": {
        "base_score": 2.4,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Project dependencies visible"
    },
    "Sensitive File Exposure: /package.json": {
        "base_score": 2.4,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Confidentiality)",
        "description": "Project dependencies visible"
    },
    
    # Sensitive File Exposure - Info
    "Sensitive File Exposure: /robots.txt": {
        "base_score": 0.0,
        "severity": "Info",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "None",
        "description": "May reveal hidden paths"
    },
    "Sensitive File Exposure: /sitemap.xml": {
        "base_score": 0.0,
        "severity": "Info",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "None",
        "description": "Site structure visible"
    }
}

def get_cvss_info(vuln_type):
    """Get CVSS scoring information for a vulnerability type"""
    if vuln_type in CVSS_SCORES:
        return CVSS_SCORES[vuln_type]
    
    # Fallback for unknown vulnerability types
    return {
        "base_score": 5.0,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Unknown",
        "description": "Unknown vulnerability type"
    }

class VulnerabilityScanner:
    def __init__(self, target_url, include_passive_checks=True):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).hostname
        self.target_port = urlparse(target_url).port
        self.include_passive_checks = include_passive_checks
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL warnings for self-signed targets
        # Spoof User-Agent
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.pages_to_scan = set()

    def crawl(self, start_url, max_pages=50):
        """
        Iterative Crawler (Stable).
        Does not use recursion, preventing crashes.
        """
        to_visit = [start_url]
        visited = set()
        
        # Static file extensions to IGNORE
        ignored_extensions = (
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', 
            '.zip', '.tar', '.gz', '.rar', 
            '.mp3', '.mp4', 
            '.css', '.js', '.ico', '.xml', '.json', '.txt'
        )

        logger.debug(f"Starting crawl on {start_url}")
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            # Pre-check extension
            path = urlparse(url).path.lower()
            if path.endswith(ignored_extensions):
                continue

            try:
                visited.add(url)
                logger.debug(f"Visiting: {url}")
                
                response = self.session.get(url, timeout=7)
                
                # Check Content-Type (skip non-html)
                ctype = response.headers.get('Content-Type', '').lower()
                if 'text/html' not in ctype:
                    continue

                # Add to our final scan list
                self.pages_to_scan.add(url)

                soup = BeautifulSoup(response.content, "html.parser")
                
                # Find new links
                for link in soup.find_all("a"):
                    href = link.attrs.get("href")
                    if href:
                        full_url = urljoin(url, href)
                        
                        # Only internal links (ignoring ports)
                        if urlparse(full_url).hostname == urlparse(self.target_url).hostname:
                            # Filter static files again for safety
                            if not urlparse(full_url).path.lower().endswith(ignored_extensions):
                                if full_url not in visited and full_url not in to_visit:
                                    to_visit.append(full_url)
                                    
            except Exception as e:
                logger.debug(f"Error visiting {url}: {e}")
                continue

    def get_forms(self, url):
        try:
            response = self.session.get(url, timeout=7)
            return BeautifulSoup(response.content, "html.parser").find_all("form")
        except:
            return []

    def form_details(self, form):
        details = {}
        action = form.attrs.get("action")
        action = action if action else self.target_url
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for idx, input_tag in enumerate(form.find_all("input")):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if not input_name:
                input_name = f"input_{idx}"
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def attackable_form_fields(self, form_details):
        return [
            input_data["name"]
            for input_data in form_details["inputs"]
            if input_data["type"] not in ['submit', 'image', 'button', 'file', 'reset', 'hidden']
        ]

    def default_form_input_value(self, input_type, input_name):
        field_name = (input_name or "").lower()
        input_type = (input_type or "text").lower()

        if input_type == "email" or "email" in field_name:
            return "vibescanner@example.com"
        if input_type in {"number", "range"}:
            return "1"
        if input_type == "password" or "pass" in field_name:
            return "Password123!"
        if input_type == "url":
            return "https://example.com"
        if input_type == "tel":
            return "9999999999"
        if input_type in {"search", "text"}:
            return "vibescannerprobe123"
        return "vibescannerprobe123"

    def _build_form_submission(self, form_details, url, value, target_field=None):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input_data in inputs:
            if input_data["type"] not in ['submit', 'image', 'button', 'file', 'reset']:
                if input_data["type"] == 'hidden':
                    data[input_data["name"]] = input_data.get("value", "")
                elif target_field and input_data["name"] != target_field:
                    data[input_data["name"]] = input_data.get("value") or self.default_form_input_value(
                        input_data["type"],
                        input_data["name"]
                    )
                else:
                    data[input_data["name"]] = value
        return target_url, data

    def submit_form(self, form_details, url, value, target_field=None):
        target_url, data = self._build_form_submission(form_details, url, value, target_field=target_field)
        try:
            if form_details["method"] == "post":
                return self.session.post(target_url, data=data, timeout=7)
            return self.session.get(target_url, params=data, timeout=7)
        except:
            return None

    def timed_submit_form(self, form_details, url, value, target_field=None):
        target_url, data = self._build_form_submission(form_details, url, value, target_field=target_field)
        start = time.perf_counter()
        try:
            if form_details["method"] == "post":
                response = self.session.post(target_url, data=data, timeout=SQLI_TIME_REQUEST_TIMEOUT_SECONDS)
            else:
                response = self.session.get(target_url, params=data, timeout=SQLI_TIME_REQUEST_TIMEOUT_SECONDS)
        except:
            return None, None
        return response, time.perf_counter() - start

    def is_vulnerable_to_sqli(self, response):
        return self.has_new_sqli_error(response)

    def extract_sqli_errors(self, text):
        if not text:
            return set()
        text = text.lower()
        return {error for error in SQLI_ERROR_PATTERNS if error in text}

    def has_new_sqli_error(self, response, baseline_response=None):
        if response is None:
            return False

        response_errors = self.extract_sqli_errors(response.text)
        if not response_errors:
            return False

        baseline_errors = set()
        baseline_status = None
        if baseline_response is not None:
            baseline_errors = self.extract_sqli_errors(getattr(baseline_response, "text", ""))
            baseline_status = getattr(baseline_response, "status_code", None)

        new_errors = response_errors - baseline_errors
        if new_errors:
            if baseline_status is None:
                return True
            if response.status_code >= 500 and baseline_status < 500:
                return True
            if response.text != getattr(baseline_response, "text", ""):
                return True

        return False

    def normalize_response_text(self, text):
        if not text:
            return ""

        soup = BeautifulSoup(text, "html.parser")
        normalized = soup.get_text(" ", strip=True)
        normalized = re.sub(r"\b\d{4,}\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized[:4000]

    def response_fingerprint(self, response):
        if response is None:
            return {
                "status": None,
                "title": "",
                "text": "",
                "length": 0
            }

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
        normalized_text = self.normalize_response_text(response.text)

        return {
            "status": response.status_code,
            "title": title,
            "text": normalized_text,
            "length": len(normalized_text)
        }

    def response_similarity(self, left, right):
        if not left and not right:
            return 1.0
        return SequenceMatcher(None, left, right).ratio()

    def default_sqli_base_value(self, original_value=""):
        value = str(original_value or "").strip()
        if not value:
            return "1"
        if any(char in value for char in (" ", "'", "\"", "(", ")")):
            return "1"
        return value[:40]

    def build_boolean_sqli_pairs(self, original_value=""):
        base_value = self.default_sqli_base_value(original_value)
        pairs = []

        for template in SQLI_BOOLEAN_TEMPLATES:
            pairs.append({
                "label": template["label"],
                "true": template["true"].format(base=base_value),
                "false": template["false"].format(base=base_value)
            })

        return pairs

    def build_time_sqli_pairs(self, original_value=""):
        base_value = self.default_sqli_base_value(original_value)
        pairs = []

        for template in SQLI_TIME_TEMPLATES:
            pairs.append({
                "label": template["label"],
                "delay": template["delay"].format(base=base_value),
                "control": template["control"].format(base=base_value)
            })

        return pairs

    def analyze_boolean_sqli(self, baseline_response, true_response, false_response):
        if baseline_response is None or true_response is None or false_response is None:
            return None

        baseline_fp = self.response_fingerprint(baseline_response)
        true_fp = self.response_fingerprint(true_response)
        false_fp = self.response_fingerprint(false_response)

        similarity_true = self.response_similarity(baseline_fp["text"], true_fp["text"])
        similarity_false = self.response_similarity(baseline_fp["text"], false_fp["text"])
        similarity_pair = self.response_similarity(true_fp["text"], false_fp["text"])
        length_gap = abs(true_fp["length"] - false_fp["length"])
        title_changed = true_fp["title"] != false_fp["title"]
        status_changed = true_fp["status"] != false_fp["status"]

        baseline_favors_true = similarity_true >= 0.97 and (similarity_true - similarity_false) >= 0.03
        materially_different = (
            status_changed or
            title_changed or
            length_gap >= 40 or
            similarity_false <= 0.94 or
            similarity_pair <= 0.94
        )

        if not (baseline_favors_true and materially_different):
            return None

        confidence = "High" if (status_changed or title_changed or length_gap >= 120) else "Medium"
        return {
            "confidence": confidence,
            "baseline_similarity": round(similarity_true, 3),
            "false_similarity": round(similarity_false, 3),
            "true_false_similarity": round(similarity_pair, 3),
            "status_changed": status_changed,
            "title_changed": title_changed,
            "length_gap": length_gap
        }

    def analyze_time_sqli(self, baseline_elapsed, delay_elapsed, control_elapsed, delay_response=None, control_response=None):
        if baseline_elapsed is None or delay_elapsed is None or control_elapsed is None:
            return None

        effective_baseline = max(baseline_elapsed, control_elapsed)
        delay_gap = delay_elapsed - effective_baseline
        control_gap = abs(control_elapsed - baseline_elapsed)

        if delay_elapsed < (SQLI_TIME_DELAY_SECONDS - 0.3):
            return None

        if delay_gap < SQLI_TIME_THRESHOLD_SECONDS:
            return None

        if control_gap > SQLI_TIME_CONTROL_TOLERANCE_SECONDS:
            return None

        delay_status = getattr(delay_response, "status_code", None)
        control_status = getattr(control_response, "status_code", None)
        confidence = "High" if delay_gap >= 2.6 else "Medium"

        return {
            "confidence": confidence,
            "baseline_seconds": round(baseline_elapsed, 3),
            "delay_seconds": round(delay_elapsed, 3),
            "control_seconds": round(control_elapsed, 3),
            "delay_gap_seconds": round(delay_gap, 3),
            "control_gap_seconds": round(control_gap, 3),
            "delay_status": delay_status,
            "control_status": control_status
        }

    def build_sqli_vulnerability(self, vuln_type, url, payload, parameter=None, detection_method="error-based", confidence="High", evidence=None):
        cvss = get_cvss_info(vuln_type)
        scope = f"parameter '{parameter}'" if parameter else "submitted input"
        method_label = detection_method.replace("-", " ")
        description = f"{method_label.title()} SQL injection indicators were observed for {scope}."
        if detection_method == "boolean-based":
            description = f"True and false SQL conditions produced meaningfully different responses for {scope}, which is consistent with boolean-based SQL injection."
        elif detection_method == "time-based":
            description = f"Delay-oriented SQL payloads caused a measurable response-time increase for {scope}, which is consistent with blind time-based SQL injection."

        vuln = {
            "type": vuln_type,
            "url": url,
            "payload": payload,
            "risk": cvss['severity'],
            "cvss_score": cvss['base_score'],
            "attack_vector": cvss['attack_vector'],
            "attack_complexity": cvss['attack_complexity'],
            "privileges_required": cvss['privileges_required'],
            "user_interaction": cvss['user_interaction'],
            "description": description,
            "confidence": confidence,
            "detection_method": detection_method
        }

        if evidence:
            vuln["evidence"] = evidence

        return vuln

    def _request_url_param_value(self, url, param_name, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            return None

        original_value = params[param_name]
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            return self.session.get(new_url, timeout=7)
        except:
            return None
        finally:
            params[param_name] = original_value

    def timed_get(self, url, **kwargs):
        start = time.perf_counter()
        try:
            response = self.session.get(url, **kwargs)
        except:
            return None, None
        return response, time.perf_counter() - start

    def _timed_request_url_param_value(self, url, param_name, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param_name not in params:
            return None, None

        original_value = params[param_name]
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            return self.timed_get(new_url, timeout=SQLI_TIME_REQUEST_TIMEOUT_SECONDS)
        finally:
            params[param_name] = original_value

    def is_vulnerable_to_xss(self, response, payload, baseline_response=None):
        if response is None or payload not in response.text:
            return False

        if baseline_response is not None and payload in getattr(baseline_response, "text", ""):
            return False

        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return False

        if not self.has_executable_xss_context(response.text, payload):
            return False

        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all(True):
            tag_markup = str(tag)

            if tag.name in XSS_DANGEROUS_TAGS and payload in tag_markup:
                return True

            for attr_name, attr_value in tag.attrs.items():
                value = " ".join(attr_value) if isinstance(attr_value, list) else str(attr_value)
                attr_name = attr_name.lower()
                if payload in value and (attr_name.startswith("on") or attr_name in XSS_DANGEROUS_ATTRS):
                    return True

        return False

    def has_executable_xss_context(self, html, payload):
        start = 0
        while True:
            idx = html.find(payload, start)
            if idx == -1:
                return False
            if not self.is_non_executable_context(html, idx):
                return True
            start = idx + len(payload)

    def is_non_executable_context(self, html, idx):
        html_lower = html.lower()

        comment_start = html_lower.rfind("<!--", 0, idx)
        comment_end = html_lower.rfind("-->", 0, idx)
        if comment_start != -1 and comment_start > comment_end:
            return True

        for tag in ("textarea", "title"):
            open_tag = html_lower.rfind(f"<{tag}", 0, idx)
            close_tag = html_lower.rfind(f"</{tag}>", 0, idx)
            if open_tag != -1 and open_tag > close_tag:
                tag_end = html_lower.find(">", open_tag)
                close_after = html_lower.find(f"</{tag}>", idx)
                if tag_end != -1 and close_after != -1 and tag_end < idx < close_after:
                    return True

        return False

    def is_vulnerable_to_lfi(self, response):
        if response is None: return False
        text = response.text.lower()
        if "root:x:0:0:" in text or "[extensions]" in text or "mysql:x:" in text or "mpextdesc" in text or "warning: include(" in text or "failed to open stream: no such file or directory" in text:
            return True
        return False

    def scan_url_parameters(self, url, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Also parse fragments to test SPA-style parameters (e.g. #/page?id=1)
        fragment_params = parse_qs(urlparse(parsed.fragment).query) if '?' in parsed.fragment else {}
        
        if not params and not fragment_params:
            return None, None

        baseline_response = None
        try:
            baseline_response = self.session.get(url, timeout=7)
        except:
            pass
            
        # Test query params First
        for param in params.keys():
            original_value = params[param]
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                res = self.session.get(new_url, timeout=7)
                if self.has_new_sqli_error(res, baseline_response):
                    return res, param
            except:
                pass
            params[param] = original_value
        return None, None

    def detect_sqli_in_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return None

        baseline_response, baseline_elapsed = self.timed_get(url, timeout=SQLI_TIME_REQUEST_TIMEOUT_SECONDS)

        for param, original_value in params.items():
            original_scalar = original_value[0] if original_value else ""

            for payload in SQLI_ERROR_PAYLOADS:
                response = self._request_url_param_value(url, param, payload)
                if self.has_new_sqli_error(response, baseline_response):
                    evidence = {
                        "technique": "error-based",
                        "sql_errors": sorted(self.extract_sqli_errors(response.text))
                    }
                    return self.build_sqli_vulnerability(
                        "SQL Injection (URL Parameter)",
                        url,
                        f"[{param}] {payload}",
                        parameter=param,
                        detection_method="error-based",
                        confidence="High",
                        evidence=evidence
                    )

            for pair in self.build_boolean_sqli_pairs(original_scalar):
                true_response = self._request_url_param_value(url, param, pair["true"])
                false_response = self._request_url_param_value(url, param, pair["false"])
                evidence = self.analyze_boolean_sqli(baseline_response, true_response, false_response)
                if evidence:
                    payload = f"[{param}] TRUE={pair['true']} | FALSE={pair['false']}"
                    evidence["technique"] = pair["label"]
                    return self.build_sqli_vulnerability(
                        "SQL Injection (URL Parameter)",
                        url,
                        payload,
                        parameter=param,
                        detection_method="boolean-based",
                        confidence=evidence["confidence"],
                        evidence=evidence
                    )

            for pair in self.build_time_sqli_pairs(original_scalar):
                delay_response, delay_elapsed = self._timed_request_url_param_value(url, param, pair["delay"])
                control_response, control_elapsed = self._timed_request_url_param_value(url, param, pair["control"])
                evidence = self.analyze_time_sqli(
                    baseline_elapsed,
                    delay_elapsed,
                    control_elapsed,
                    delay_response=delay_response,
                    control_response=control_response
                )
                if evidence:
                    payload = f"[{param}] DELAY={pair['delay']} | CONTROL={pair['control']}"
                    evidence["technique"] = pair["label"]
                    return self.build_sqli_vulnerability(
                        "SQL Injection (URL Parameter)",
                        url,
                        payload,
                        parameter=param,
                        detection_method="time-based",
                        confidence=evidence["confidence"],
                        evidence=evidence
                    )

        return None

    def scan_lfi_url_parameters(self, url, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None, None

        for param in params.keys():
            original_value = params[param]
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                res = self.session.get(new_url, timeout=7)
                if self.is_vulnerable_to_lfi(res):
                    return res, param
            except:
                pass
            params[param] = original_value
        return None, None

    def scan_xss_url_parameters(self, url, payload):
        """Test XSS in URL query parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None, None

        baseline_response = None
        try:
            baseline_response = self.session.get(url, timeout=7)
        except:
            pass

        for param in params.keys():
            original_value = params[param]
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                res = self.session.get(new_url, timeout=7)
                if self.is_vulnerable_to_xss(res, payload, baseline_response):
                    return res, param
            except:
                pass
            params[param] = original_value
        return None, None

    def detect_sqli_in_form(self, form_details, url):
        field_names = self.attackable_form_fields(form_details)
        if not field_names:
            return None

        for field_name in field_names:
            baseline_value = self.default_form_input_value("text", field_name)
            baseline_response, baseline_elapsed = self.timed_submit_form(
                form_details,
                url,
                baseline_value,
                target_field=field_name
            )

            for payload in SQLI_ERROR_PAYLOADS:
                response = self.submit_form(form_details, url, payload, target_field=field_name)
                if self.has_new_sqli_error(response, baseline_response):
                    evidence = {
                        "technique": "error-based",
                        "sql_errors": sorted(self.extract_sqli_errors(response.text))
                    }
                    return self.build_sqli_vulnerability(
                        "SQL Injection (Form)",
                        url,
                        f"[{field_name}] {payload}",
                        parameter=field_name,
                        detection_method="error-based",
                        confidence="High",
                        evidence=evidence
                    )

            for pair in self.build_boolean_sqli_pairs():
                true_response = self.submit_form(form_details, url, pair["true"], target_field=field_name)
                false_response = self.submit_form(form_details, url, pair["false"], target_field=field_name)
                evidence = self.analyze_boolean_sqli(baseline_response, true_response, false_response)
                if evidence:
                    payload = f"[{field_name}] TRUE={pair['true']} | FALSE={pair['false']}"
                    evidence["technique"] = pair["label"]
                    return self.build_sqli_vulnerability(
                        "SQL Injection (Form)",
                        url,
                        payload,
                        parameter=field_name,
                        detection_method="boolean-based",
                        confidence=evidence["confidence"],
                        evidence=evidence
                    )

            for pair in self.build_time_sqli_pairs(baseline_value):
                delay_response, delay_elapsed = self.timed_submit_form(
                    form_details,
                    url,
                    pair["delay"],
                    target_field=field_name
                )
                control_response, control_elapsed = self.timed_submit_form(
                    form_details,
                    url,
                    pair["control"],
                    target_field=field_name
                )
                evidence = self.analyze_time_sqli(
                    baseline_elapsed,
                    delay_elapsed,
                    control_elapsed,
                    delay_response=delay_response,
                    control_response=control_response
                )
                if evidence:
                    payload = f"[{field_name}] DELAY={pair['delay']} | CONTROL={pair['control']}"
                    evidence["technique"] = pair["label"]
                    return self.build_sqli_vulnerability(
                        "SQL Injection (Form)",
                        url,
                        payload,
                        parameter=field_name,
                        detection_method="time-based",
                        confidence=evidence["confidence"],
                        evidence=evidence
                    )

        return None

    def parse_csp_directives(self, csp_value):
        directives = {}
        if not csp_value:
            return directives

        for directive in csp_value.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            name = parts[0].lower()
            directives[name] = parts[1:]

        return directives

    def has_effective_hsts(self, header_value):
        if not header_value:
            return False

        match = re.search(r"max-age\s*=\s*(\d+)", header_value, re.IGNORECASE)
        if not match:
            return False

        try:
            return int(match.group(1)) > 0
        except ValueError:
            return False

    def build_security_header_finding(self, url, response_url, header_name, description, evidence):
        vuln_type = f"Missing Security Header: {header_name}"
        cvss = get_cvss_info(vuln_type)
        return {
            "type": vuln_type,
            "url": response_url or url,
            "description": description,
            "risk": cvss["severity"],
            "cvss_score": cvss["base_score"],
            "attack_vector": cvss["attack_vector"],
            "attack_complexity": cvss["attack_complexity"],
            "privileges_required": cvss["privileges_required"],
            "user_interaction": cvss["user_interaction"],
            "confidence": PASSIVE_HARDENING_CONFIDENCE,
            "detection_method": PASSIVE_HARDENING_METHOD,
            "evidence": evidence
        }

    def check_security_headers(self, url):
        """Check passive hardening headers with context-aware rules."""
        vulnerabilities = []
        try:
            response = self.session.get(url, timeout=7)
            headers = {k.lower(): v for k, v in response.headers.items()}
            response_url = getattr(response, "url", url)
            effective_scheme = urlparse(response_url).scheme.lower()
            csp_directives = self.parse_csp_directives(headers.get("content-security-policy", ""))

            if "x-frame-options" not in headers and "frame-ancestors" not in csp_directives:
                vulnerabilities.append(self.build_security_header_finding(
                    url,
                    response_url,
                    "X-Frame-Options",
                    "Hardening advisory: the response does not define X-Frame-Options and the CSP also lacks frame-ancestors, so clickjacking defenses are weaker.",
                    {
                        "check_type": "security-header-hardening",
                        "missing_header": "x-frame-options",
                        "csp_frame_ancestors_present": False
                    }
                ))

            if "content-security-policy" not in headers:
                vulnerabilities.append(self.build_security_header_finding(
                    url,
                    response_url,
                    "Content-Security-Policy",
                    "Hardening advisory: the response does not define a Content-Security-Policy header, so browser-side injection mitigation is reduced.",
                    {
                        "check_type": "security-header-hardening",
                        "missing_header": "content-security-policy"
                    }
                ))

            if effective_scheme == "https" and not self.has_effective_hsts(headers.get("strict-transport-security", "")):
                vulnerabilities.append(self.build_security_header_finding(
                    url,
                    response_url,
                    "Strict-Transport-Security",
                    "Hardening advisory: the HTTPS response does not define an effective Strict-Transport-Security policy, so downgrade protection is weaker.",
                    {
                        "check_type": "security-header-hardening",
                        "missing_header": "strict-transport-security",
                        "effective_scheme": effective_scheme,
                        "observed_header": headers.get("strict-transport-security", "")
                    }
                ))

            if headers.get("x-content-type-options", "").lower() != "nosniff":
                vulnerabilities.append(self.build_security_header_finding(
                    url,
                    response_url,
                    "X-Content-Type-Options",
                    "Hardening advisory: the response does not enforce X-Content-Type-Options: nosniff, so MIME sniffing protections are weaker.",
                    {
                        "check_type": "security-header-hardening",
                        "missing_header": "x-content-type-options",
                        "observed_header": headers.get("x-content-type-options", "")
                    }
                ))

            if "referrer-policy" not in headers:
                vulnerabilities.append(self.build_security_header_finding(
                    url,
                    response_url,
                    "Referrer-Policy",
                    "Hardening advisory: the response does not define a Referrer-Policy header, so referrer leakage controls are absent.",
                    {
                        "check_type": "security-header-hardening",
                        "missing_header": "referrer-policy"
                    }
                ))

            if "permissions-policy" not in headers:
                vulnerabilities.append(self.build_security_header_finding(
                    url,
                    response_url,
                    "Permissions-Policy",
                    "Hardening advisory: the response does not define a Permissions-Policy header, so browser feature restrictions are not declared.",
                    {
                        "check_type": "security-header-hardening",
                        "missing_header": "permissions-policy"
                    }
                ))
        except Exception as e:
            logger.debug(f"Error checking security headers for {url}: {e}")
        
        return vulnerabilities

    def check_sensitive_files(self, base_url):
        """Check for exposed sensitive files and directories"""
        vulnerabilities = []
        
        sensitive_paths = {
            '/.git/': {'risk': 'Critical', 'description': 'Git repository exposed - source code and commit history accessible'},
            '/.git/config': {'risk': 'Critical', 'description': 'Git config file exposed - may contain credentials'},
            '/.env': {'risk': 'Critical', 'description': 'Environment file exposed - may contain database passwords and API keys'},
            '/config.php': {'risk': 'High', 'description': 'PHP config file exposed - may contain database credentials'},
            '/wp-config.php': {'risk': 'High', 'description': 'WordPress config exposed - contains database credentials'},
            '/backup.sql': {'risk': 'Critical', 'description': 'SQL backup file exposed - entire database may be downloadable'},
            '/database.sql': {'risk': 'Critical', 'description': 'SQL database file exposed - entire database may be downloadable'},
            '/db.sql': {'risk': 'Critical', 'description': 'SQL database file exposed - entire database may be downloadable'},
            '/dump.sql': {'risk': 'Critical', 'description': 'SQL dump file exposed - entire database may be downloadable'},
            '/.htpasswd': {'risk': 'High', 'description': 'htpasswd file exposed - contains hashed passwords'},
            '/.htaccess': {'risk': 'Medium', 'description': 'htaccess file exposed - server configuration visible'},
            '/phpinfo.php': {'risk': 'Medium', 'description': 'PHP info page exposed - server configuration and paths visible'},
            '/info.php': {'risk': 'Medium', 'description': 'PHP info page exposed - server configuration and paths visible'},
            '/server-status': {'risk': 'Medium', 'description': 'Apache server status exposed - internal server info visible'},
            '/web.config': {'risk': 'High', 'description': 'IIS web.config exposed - may contain credentials'},
            '/.svn/': {'risk': 'High', 'description': 'SVN repository exposed - source code accessible'},
            '/.DS_Store': {'risk': 'Low', 'description': 'macOS DS_Store file exposed - directory structure visible'},
            '/robots.txt': {'risk': 'Info', 'description': 'Robots.txt found - may reveal hidden paths'},
            '/sitemap.xml': {'risk': 'Info', 'description': 'Sitemap found - site structure visible'},
            '/crossdomain.xml': {'risk': 'Low', 'description': 'Flash crossdomain policy found - may allow cross-domain access'},
            '/clientaccesspolicy.xml': {'risk': 'Low', 'description': 'Silverlight access policy found - may allow cross-domain access'},
            '/error_log': {'risk': 'Medium', 'description': 'Error log exposed - may contain sensitive debugging info'},
            '/debug.log': {'risk': 'Medium', 'description': 'Debug log exposed - may contain sensitive debugging info'},
            '/.bash_history': {'risk': 'High', 'description': 'Bash history exposed - may contain commands with credentials'},
            '/id_rsa': {'risk': 'Critical', 'description': 'Private SSH key exposed - critical security breach'},
            '/id_rsa.pub': {'risk': 'Low', 'description': 'Public SSH key exposed'},
            '/composer.json': {'risk': 'Low', 'description': 'Composer file exposed - project dependencies visible'},
            '/package.json': {'risk': 'Low', 'description': 'Package.json exposed - project dependencies visible'}
        }
        
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path, info in sensitive_paths.items():
            try:
                test_url = urljoin(base, path)
                response = self.session.get(test_url, timeout=7, allow_redirects=False)
                
                # Check for successful response (not 404, 403, or redirect)
                if response.status_code == 200:
                    # Additional validation to reduce false positives
                    content_length = len(response.content)
                    if content_length > 0:
                        # Check it's not a custom 404 page
                        if 'not found' not in response.text.lower()[:500] and '404' not in response.text.lower()[:500]:
                            vuln_type = f'Sensitive File Exposure: {path}'
                            cvss = get_cvss_info(vuln_type)
                            vulnerabilities.append({
                                'type': vuln_type,
                                'url': test_url,
                                'description': info['description'],
                                'risk': cvss['severity'],
                                'cvss_score': cvss['base_score'],
                                'attack_vector': cvss['attack_vector'],
                                'attack_complexity': cvss['attack_complexity'],
                                'privileges_required': cvss['privileges_required'],
                                'user_interaction': cvss['user_interaction']
                            })
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")
                continue
        
        return vulnerabilities

    def run_scan(self):
        try:
            yield f"data: [INFO] Starting crawler on {self.target_url}...\n\n"
            logger.info(f"Starting crawler on {self.target_url}")
            
            # 0. Auth bypass for pentest-ground.com targets
            if self.target_domain and "pentest-ground.com" in self.target_domain:
                yield "data: [INFO] Target is pentest-ground.com - Attempting default logins...\n\n"
                try:
                    if self.target_port in [4280, "4280"]:  # DVWA
                        login_url = urljoin(self.target_url, "/login.php")
                        res = self.session.get(login_url, timeout=7)
                        soup = BeautifulSoup(res.text, "html.parser")
                        token_input = soup.find("input", {"name": "user_token"})
                        token = token_input.get("value") if token_input else ""
                        self.session.post(login_url, data={"username": "admin", "password": "password", "Login": "Login", "user_token": token}, timeout=7)
                        
                        # Set security to low
                        security_url = urljoin(self.target_url, "/security.php")
                        self.session.post(security_url, data={"security": "low", "seclev_submit": "Submit", "user_token": token}, timeout=7)
                        yield "data: [INFO] Logged into DVWA and set security to low.\n\n"
                        
                    elif self.target_port in [81, "81"]:  # bWAPP
                        login_url = urljoin(self.target_url, "/login.php")
                        self.session.post(login_url, data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"}, timeout=7)
                        yield "data: [INFO] Logged into bWAPP.\n\n"
                        
                except Exception as e:
                    logger.debug(f"Auth bypass failed: {e}")
            
            # 1. Run the iterative crawler
            self.crawl(self.target_url)
            
            count = len(self.pages_to_scan)
            logger.debug(f"Crawler finished. Found {count} pages.")
            yield f"data: [INFO] Crawling complete. Found {count} pages.\n\n"

            # 2. Passive hardening checks (only on main URL)
            if self.include_passive_checks:
                yield "data: [INFO] Running passive hardening checks (security headers)...\n\n"
                header_vulns = self.check_security_headers(self.target_url)
                for vuln in header_vulns:
                    yield f"data: [VULN] {json.dumps(vuln)}\n\n"
            else:
                yield "data: [INFO] Skipping passive hardening checks.\n\n"
            
            # 3. Check for Sensitive Files
            yield f"data: [INFO] Checking for sensitive file exposure...\n\n"
            file_vulns = self.check_sensitive_files(self.target_url)
            for vuln in file_vulns:
                yield f"data: [VULN] {json.dumps(vuln)}\n\n"

            lfi_payloads = ["../../../etc/passwd", "../../../../etc/passwd", "/etc/passwd", "../../../windows/win.ini", "../../../../windows/win.ini", "c:/windows/win.ini"]
            xss_payloads = ["<script>alert('XSS')</script>","<img src=x onerror=alert(1)>","<svg onload=alert(1)>","<script>alert(/XSS/)</script>","<IMG SRC=jAVasCrIPt:alert(�XSS�)>","<svg/onload=alert('XSS')>","<BODY ONLOAD=alert('XSS')>"]
            
            # 2. Scan pages
            for link in self.pages_to_scan:
                logger.debug(f"Scanning: {link}")
                yield f"data: [INFO] Scanning page: {link}\n\n" 
                
                # A. Scan URL Params for SQLi
                if "?" in link:
                    vuln = self.detect_sqli_in_url(link)
                    if vuln:
                        yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                
                # B. Scan URL Params for XSS
                if "?" in link:
                    for payload in xss_payloads:
                        res, param = self.scan_xss_url_parameters(link, payload)
                        if res is not None:
                            vuln_type = "XSS (URL Parameter)"
                            cvss = get_cvss_info(vuln_type)
                            vuln = {
                                "type": vuln_type,
                                "url": link,
                                "payload": f"[{param}] {payload}",
                                "risk": cvss['severity'],
                                "cvss_score": cvss['base_score'],
                                "attack_vector": cvss['attack_vector'],
                                "attack_complexity": cvss['attack_complexity'],
                                "privileges_required": cvss['privileges_required'],
                                "user_interaction": cvss['user_interaction']
                            }
                            yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                            break

                # C. Scan URL Params for LFI
                if "?" in link:
                    for payload in lfi_payloads:
                        res, param = self.scan_lfi_url_parameters(link, payload)
                        if res is not None:
                            vuln_type = "Local File Inclusion (URL Parameter)"
                            cvss = get_cvss_info(vuln_type)
                            vuln = {
                                "type": vuln_type,
                                "url": link,
                                "payload": f"[{param}] {payload}",
                                "risk": cvss['severity'],
                                "cvss_score": cvss['base_score'],
                                "attack_vector": cvss['attack_vector'],
                                "attack_complexity": cvss['attack_complexity'],
                                "privileges_required": cvss['privileges_required'],
                                "user_interaction": cvss['user_interaction']
                            }
                            yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                            break
                
                # D. Scan Forms
                forms = self.get_forms(link)
                for form in forms:
                    details = self.form_details(form)
                    attackable_fields = self.attackable_form_fields(details)
                    
                    # SQLi on Forms
                    sqli_vuln = self.detect_sqli_in_form(details, link)
                    if sqli_vuln:
                        yield f"data: [VULN] {json.dumps(sqli_vuln)}\n\n"

                    # XSS on Forms
                    for field_name in attackable_fields:
                        baseline_form_response = self.submit_form(
                            details,
                            link,
                            self.default_form_input_value("text", field_name),
                            target_field=field_name
                        )
                        xss_found = False
                        for payload in xss_payloads:
                            res = self.submit_form(details, link, payload, target_field=field_name)
                            if self.is_vulnerable_to_xss(res, payload, baseline_form_response):
                                vuln_type = "XSS (Form)"
                                cvss = get_cvss_info(vuln_type)
                                vuln = {
                                    "type": vuln_type,
                                    "url": link,
                                    "payload": f"[{field_name}] {payload}",
                                    "risk": cvss['severity'],
                                    "cvss_score": cvss['base_score'],
                                    "attack_vector": cvss['attack_vector'],
                                    "attack_complexity": cvss['attack_complexity'],
                                    "privileges_required": cvss['privileges_required'],
                                    "user_interaction": cvss['user_interaction']
                                }
                                yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                                xss_found = True
                                break
                        if xss_found:
                            break

                    # LFI on Forms
                    for field_name in attackable_fields:
                        lfi_found = False
                        for payload in lfi_payloads:
                            res = self.submit_form(details, link, payload, target_field=field_name)
                            if self.is_vulnerable_to_lfi(res):
                                vuln_type = "Local File Inclusion (Form)"
                                cvss = get_cvss_info(vuln_type)
                                vuln = {
                                    "type": vuln_type,
                                    "url": link,
                                    "payload": f"[{field_name}] {payload}",
                                    "risk": cvss['severity'],
                                    "cvss_score": cvss['base_score'],
                                    "attack_vector": cvss['attack_vector'],
                                    "attack_complexity": cvss['attack_complexity'],
                                    "privileges_required": cvss['privileges_required'],
                                    "user_interaction": cvss['user_interaction']
                                }
                                yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                                lfi_found = True
                                break
                        if lfi_found:
                            break

            yield "data: [DONE] Scan Completed.\n\n"

        except Exception as e:
            logger.critical(f"Scan failed with error: {traceback.format_exc()}")
            yield f"data: [INFO] Critical Error: {str(e)}\n\n"
            yield "data: [DONE] Scan Failed.\n\n"
