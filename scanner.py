import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import json
import traceback
import time
from logger_config import get_logger

logger = get_logger(__name__)

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
        "base_score": 4.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Integrity)",
        "description": "Site can be embedded in iframes, enabling clickjacking attacks"
    },
    "Missing Security Header: Content-Security-Policy": {
        "base_score": 5.3,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "Low (Integrity)",
        "description": "No protection against XSS and data injection attacks"
    },
    "Missing Security Header: X-Xss-Protection": {
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Integrity)",
        "description": "Browser XSS filter not explicitly enabled"
    },
    "Missing Security Header: Strict-Transport-Security": {
        "base_score": 5.9,
        "severity": "Medium",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "None",
        "impact": "High (Confidentiality)",
        "description": "Vulnerable to HTTPS downgrade and MITM attacks"
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
        "base_score": 3.1,
        "severity": "Low",
        "attack_vector": "Network",
        "attack_complexity": "High",
        "privileges_required": "None",
        "user_interaction": "Required",
        "impact": "Low (Confidentiality)",
        "description": "Referrer information may leak to third parties"
    },
    "Missing Security Header: Permissions-Policy": {
        "base_score": 2.4,
        "severity": "Low",
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
    def __init__(self, target_url):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        self.session = requests.Session()
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
                
                response = self.session.get(url, timeout=3)
                
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
                        
                        # Only internal links
                        if urlparse(full_url).netloc == self.target_domain:
                            # Filter static files again for safety
                            if not urlparse(full_url).path.lower().endswith(ignored_extensions):
                                if full_url not in visited and full_url not in to_visit:
                                    to_visit.append(full_url)
                                    
            except Exception as e:
                logger.debug(f"Error visiting {url}: {e}")
                continue

    def get_forms(self, url):
        try:
            response = self.session.get(url, timeout=3)
            return BeautifulSoup(response.content, "html.parser").find_all("form")
        except:
            return []

    def form_details(self, form):
        details = {}
        action = form.attrs.get("action")
        action = action.lower() if action else self.target_url
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input_data in inputs:
            if input_data["type"] not in ['submit', 'image', 'button', 'file', 'reset']:
                data[input_data["name"]] = value
        try:
            if form_details["method"] == "post":
                return self.session.post(target_url, data=data, timeout=3)
            return self.session.get(target_url, params=data, timeout=3)
        except:
            return None

    def is_vulnerable_to_sqli(self, response):
        if not response: return False
        # Lowercase everything for easier matching
        text = response.text.lower()
        
        errors = {
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
        for error in errors:
            if error in text:
                return True
        return False

    def scan_url_parameters(self, url, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None 

        for param in params.keys():
            original_value = params[param]
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                res = self.session.get(new_url, timeout=3)
                if self.is_vulnerable_to_sqli(res):
                    return res
            except:
                pass
            params[param] = original_value
        return None

    def scan_xss_url_parameters(self, url, payload):
        """Test XSS in URL query parameters"""
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
                res = self.session.get(new_url, timeout=3)
                if res and payload in res.text:
                    return res, param
            except:
                pass
            params[param] = original_value
        return None, None

    def check_security_headers(self, url):
        """Check for missing security headers"""
        vulnerabilities = []
        try:
            response = self.session.get(url, timeout=3)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            security_headers = {
                'x-frame-options': {
                    'risk': 'Medium',
                    'description': 'Missing X-Frame-Options header - site may be vulnerable to clickjacking attacks'
                },
                'content-security-policy': {
                    'risk': 'Medium',
                    'description': 'Missing Content-Security-Policy header - no protection against XSS and data injection attacks'
                },
                'x-xss-protection': {
                    'risk': 'Low',
                    'description': 'Missing X-XSS-Protection header - browser XSS filter not enabled'
                },
                'strict-transport-security': {
                    'risk': 'Medium',
                    'description': 'Missing Strict-Transport-Security header - vulnerable to protocol downgrade attacks'
                },
                'x-content-type-options': {
                    'risk': 'Low',
                    'description': 'Missing X-Content-Type-Options header - vulnerable to MIME type sniffing'
                },
                'referrer-policy': {
                    'risk': 'Low',
                    'description': 'Missing Referrer-Policy header - referrer information may leak to third parties'
                },
                'permissions-policy': {
                    'risk': 'Low',
                    'description': 'Missing Permissions-Policy header - browser features not restricted'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    vuln_type = f'Missing Security Header: {header.title()}'
                    cvss = get_cvss_info(vuln_type)
                    vulnerabilities.append({
                        'type': vuln_type,
                        'url': url,
                        'description': info['description'],
                        'risk': cvss['severity'],
                        'cvss_score': cvss['base_score'],
                        'attack_vector': cvss['attack_vector'],
                        'attack_complexity': cvss['attack_complexity'],
                        'privileges_required': cvss['privileges_required'],
                        'user_interaction': cvss['user_interaction']
                    })
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
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
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
            
            # 1. Run the iterative crawler
            self.crawl(self.target_url)
            
            count = len(self.pages_to_scan)
            logger.debug(f"Crawler finished. Found {count} pages.")
            yield f"data: [INFO] Crawling complete. Found {count} pages.\n\n"

            # 2. Check Security Headers (only on main URL)
            yield f"data: [INFO] Checking security headers...\n\n"
            header_vulns = self.check_security_headers(self.target_url)
            for vuln in header_vulns:
                yield f"data: [VULN] {json.dumps(vuln)}\n\n"
            
            # 3. Check for Sensitive Files
            yield f"data: [INFO] Checking for sensitive file exposure...\n\n"
            file_vulns = self.check_sensitive_files(self.target_url)
            for vuln in file_vulns:
                yield f"data: [VULN] {json.dumps(vuln)}\n\n"

            sqli_payloads = ["'", "\"", "' OR '1'='1","OR 1=1","' OR '1","1' ORDER BY 1,2,3--+","-1 UNION SELECT 1 INTO @,@,@"]
            xss_payloads = ["<script>alert('XSS')</script>","<img src=x onerror=alert(1)>","<svg onload=alert(1)>","<script>alert(/XSS/)</script>","<IMG SRC=jAVasCrIPt:alert(�XSS�)>","<svg/onload=alert('XSS')>","<BODY ONLOAD=alert('XSS')>"]
            
            # 2. Scan pages
            for link in self.pages_to_scan:
                logger.debug(f"Scanning: {link}")
                yield f"data: [INFO] Scanning page: {link}\n\n" 
                
                # A. Scan URL Params for SQLi
                if "?" in link:
                    for payload in sqli_payloads:
                        res = self.scan_url_parameters(link, payload)
                        if res:
                            vuln_type = "SQL Injection (URL Parameter)"
                            cvss = get_cvss_info(vuln_type)
                            vuln = {
                                "type": vuln_type,
                                "url": link,
                                "payload": payload,
                                "risk": cvss['severity'],
                                "cvss_score": cvss['base_score'],
                                "attack_vector": cvss['attack_vector'],
                                "attack_complexity": cvss['attack_complexity'],
                                "privileges_required": cvss['privileges_required'],
                                "user_interaction": cvss['user_interaction']
                            }
                            yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                            break
                
                # B. Scan URL Params for XSS
                if "?" in link:
                    for payload in xss_payloads:
                        res, param = self.scan_xss_url_parameters(link, payload)
                        if res:
                            vuln_type = "XSS (URL Parameter)"
                            cvss = get_cvss_info(vuln_type)
                            vuln = {
                                "type": vuln_type,
                                "url": link,
                                "payload": payload,
                                "parameter": param,
                                "risk": cvss['severity'],
                                "cvss_score": cvss['base_score'],
                                "attack_vector": cvss['attack_vector'],
                                "attack_complexity": cvss['attack_complexity'],
                                "privileges_required": cvss['privileges_required'],
                                "user_interaction": cvss['user_interaction']
                            }
                            yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                            break
                
                # C. Scan Forms
                forms = self.get_forms(link)
                for form in forms:
                    details = self.form_details(form)
                    
                    # SQLi on Forms
                    for payload in sqli_payloads:
                        res = self.submit_form(details, link, payload)
                        if self.is_vulnerable_to_sqli(res):
                            vuln_type = "SQL Injection (Form)"
                            cvss = get_cvss_info(vuln_type)
                            vuln = {
                                "type": vuln_type,
                                "url": link,
                                "payload": payload,
                                "risk": cvss['severity'],
                                "cvss_score": cvss['base_score'],
                                "attack_vector": cvss['attack_vector'],
                                "attack_complexity": cvss['attack_complexity'],
                                "privileges_required": cvss['privileges_required'],
                                "user_interaction": cvss['user_interaction']
                            }
                            yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                            break 

                    # XSS on Forms
                    for payload in xss_payloads:
                        res = self.submit_form(details, link, payload)
                        if res and payload in res.text:
                            vuln_type = "XSS (Form)"
                            cvss = get_cvss_info(vuln_type)
                            vuln = {
                                "type": vuln_type,
                                "url": link,
                                "payload": payload,
                                "risk": cvss['severity'],
                                "cvss_score": cvss['base_score'],
                                "attack_vector": cvss['attack_vector'],
                                "attack_complexity": cvss['attack_complexity'],
                                "privileges_required": cvss['privileges_required'],
                                "user_interaction": cvss['user_interaction']
                            }
                            yield f"data: [VULN] {json.dumps(vuln)}\n\n"
                            break

            yield "data: [DONE] Scan Completed.\n\n"

        except Exception as e:
            logger.critical(f"Scan failed with error: {traceback.format_exc()}")
            yield f"data: [INFO] Critical Error: {str(e)}\n\n"
            yield "data: [DONE] Scan Failed.\n\n"