import asyncio
import aiohttp
import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import sys

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class FakeColor:
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
        WHITE = ''
        BOLD = ''
        RESET = ''
    Fore = Style = FakeColor

# --- Configuration ---
CONCURRENT_TASKS = 50
TIMEOUT = aiohttp.ClientTimeout(total=15)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# --- Vulnerability Signatures & Rules ---
SQLI_PATTERNS = [
    r"' OR '1'='1",
    r"UNION SELECT",
    r"Error converting data type varchar to numeric",
    r"MySQL Syntax Error",
    r"Oracle DB Error",
    r"PostgreSQL query failed",
    r"SQL Server Error",
    r"Unclosed quotation mark",
    r"ORA-00933",
    r"Syntax error in FROM clause"
]

OPEN_REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'dest', 'goto']

COMMON_FILES = [
    "/.env", "/wp-config.php.bak", "/backup.zip", "/database.sql", 
    "/config.yml", "/server-status", "/phpinfo.php", "/.git/config",
    "/robots.txt", "/sitemap.xml", "/admin/login"
]

class Vulnerability:
    def __init__(self, name, severity, description, evidence, url=""):
        self.name = name
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.url = url

    def __str__(self):
        color = Fore.YELLOW
        if self.severity == "Critical": color = Fore.RED
        elif self.severity == "High": color = Fore.RED
        elif self.severity == "Medium": color = Fore.YELLOW
        else: color = Fore.GREEN
        
        return f"{color}[{self.severity}] {self.name}{Style.RESET_ALL}\n" \
               f"   URL: {Fore.WHITE}{self.url}{Style.RESET_ALL}\n" \
               f"   Desc: {self.description}\n" \
               f"   Evidence: {self.evidence[:100]}...\n"

class AdvancedVulnScanner:
    def __init__(self, target_url):
        self.target = urlparse(target_url)
        self.base_url = f"{self.target.scheme}://{self.target.netloc}"
        self.scheme = self.target.scheme
        self.host = self.target.netloc
        self.headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        self.vulnerabilities = []
        self.session = None
        self.found_tech = set()

    async def __aenter__(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        self.session = aiohttp.ClientSession(
            headers=self.headers, 
            timeout=TIMEOUT,
            connector=aiohttp.TCPConnector(ssl=ssl_context)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def fetch(self, url, method="GET", params=None, data=None):
        try:
            async with self.session.request(
                method, 
                url, 
                params=params, 
                data=data,
                allow_redirects=True
            ) as response:
                body = await response.text()
                headers = dict(response.headers)
                return {
                    "status_code": response.status,
                    "headers": headers,
                    "body": body,
                    "url": url,
                    "final_url": str(response.url)
                }
        except Exception as e:
            return {"error": str(e), "url": url}

    async def detect_technology(self):
        res = await self.fetch(self.base_url)
        if "error" in res: return
        
        body = res["body"]
        headers = res["headers"]
        
        if "Server" in headers:
            server = headers["Server"].lower()
            if "apache" in server: self.found_tech.add("Apache")
            if "nginx" in server: self.found_tech.add("Nginx")
            if "iis" in server: self.found_tech.add("IIS")
            
        tech_signatures = {
            "WordPress": r'<meta name="generator" content="WordPress',
            "jQuery": r'jquery\.js',
            "React": r'data-reactroot',
            "Bootstrap": r'bootstrap\.css',
            "PHP": r'PHP/\d+\.\d+',
            "ASP.NET": r'__VIEWSTATE'
        }
        
        for tech, pattern in tech_signatures.items():
            if re.search(pattern, body, re.IGNORECASE):
                self.found_tech.add(tech)

    async def check_http_methods(self):
        methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        tasks = []
        for method in methods:
            tasks.append(self.fetch(self.base_url, method=method))
        
        results = await asyncio.gather(*tasks)
        enabled_methods = []
        for res, method in zip(results, methods):
            if "error" not in res and res["status_code"] != 405: 
                enabled_methods.append(method)
        
        if "TRACE" in enabled_methods:
            self.vulnerabilities.append(Vulnerability(
                name="HTTP TRACE Enabled",
                severity="Medium",
                description="TRACE method is enabled. Can be used for Cross-Site Tracing (XST).",
                evidence="TRACE method returned 200 OK",
                url=self.base_url
            ))
        if "OPTIONS" in enabled_methods:
            res_opts = [r for r, m in zip(results, methods) if m == "OPTIONS"][0]
            origin = res_opts["headers"].get("Access-Control-Allow-Origin", "")
            if origin == "*":
                self.vulnerabilities.append(Vulnerability(
                    name="CORS Wildcard Origin",
                    severity="Medium",
                    description="CORS allows requests from any origin (*).",
                    evidence="Access-Control-Allow-Origin: *",
                    url=self.base_url
                ))

    async def check_headers(self):
        res = await self.fetch(self.base_url)
        if "error" in res: return
        
        headers_lower = {k.lower(): v for k, v in res["headers"].items()}
        
        checks = [
            ("X-Content-Type-Options", "Missing X-Content-Type-Options header (MIME sniffing risk)", "Medium"),
            ("X-Frame-Options", "Missing X-Frame-Options header (Clickjacking risk)", "Medium"),
            ("Strict-Transport-Security", "Missing HSTS header (SSL Stripping risk)", "High"),
            ("Content-Security-Policy", "Missing CSP header (XSS risk)", "Medium"),
            ("X-XSS-Protection", "Missing XSS Protection header", "Low"),
            ("Cache-Control", "No Cache-Control header set", "Low"),
        ]
        
        for header, desc, severity in checks:
            if header.lower() not in headers_lower:
                self.vulnerabilities.append(Vulnerability(
                    name=f"Missing Header: {header}",
                    severity=severity,
                    description=desc,
                    evidence=f"Header '{header}' not found.",
                    url=self.base_url
                ))

    async def check_sql_injection(self):
        test_urls = [self.base_url]
        separator = "?" if "?" not in self.base_url else "&"
        test_url = f"{self.base_url}{separator}id=1' OR '1'='1"
        
        res = await self.fetch(test_url)
        if "error" in res: return
        
        body = res["body"]
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                self.vulnerabilities.append(Vulnerability(
                    name="SQL Injection (Error-Based)",
                    severity="High",
                    description="Potential SQL injection found via error message.",
                    evidence=f"Pattern matched in response: {pattern}",
                    url=test_url
                ))
                break

    async def check_xss(self):
        test_param = "xss_test"
        separator = "?" if "?" not in self.base_url else "&"
        test_url = f"{self.base_url}{separator}{test_param}=<script>alert(1)</script>"
        
        res = await self.fetch(test_url)
        if "error" in res: return
        
        body = res["body"]
        if re.search(r'<script>alert\(1\)</script>', body, re.IGNORECASE):
            self.vulnerabilities.append(Vulnerability(
                name="Reflected XSS",
                severity="High",
                description="XSS payload reflected in response.",
                evidence=f"Payload found in: {test_param}",
                url=test_url
            ))

    async def check_open_redirect(self):
        test_urls = []
        separator = "?" if "?" not in self.base_url else "&"
        
        for param in OPEN_REDIRECT_PARAMS:
            url = f"{self.base_url}{separator}{param}=https://evil.com"
            test_urls.append(url)
            
        tasks = [self.fetch(url) for url in test_urls]
        results = await asyncio.gather(*tasks)
        
        for res, url in zip(results, test_urls):
            if "error" not in res:
                if "evil.com" in res["final_url"]:
                    self.vulnerabilities.append(Vulnerability(
                        name="Open Redirect",
                        severity="Medium",
                        description=f"URL redirects to external domain via {param} parameter.",
                        evidence=f"Redirected to: {res['final_url']}",
                        url=url
                    ))

    async def check_common_files(self):
        tasks = []
        for path in COMMON_FILES:
            url = f"{self.base_url}{path}"
            tasks.append(self.fetch(url))
            
        results = await asyncio.gather(*tasks)
        
        for res, path in zip(results, COMMON_FILES):
            if "error" not in res and res["status_code"] == 200:
                content_type = res["headers"].get("Content-Type", "")
                if "text/html" in content_type or "json" in content_type:
                    self.vulnerabilities.append(Vulnerability(
                        name=f"Common File/Path Found: {path}",
                        severity="Low",
                        description=f"Accessible resource found at {path}.",
                        evidence=f"Status 200 OK, Content-Type: {content_type}",
                        url=res["url"]
                    ))

    async def check_ssl_details(self):
        if self.scheme == "https":
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.host, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        cert = ssock.getpeercert()
                        if "subject" in cert:
                            self.found_tech.add("SSL/TLS")
                            
            except Exception as e:
                self.vulnerabilities.append(Vulnerability(
                    name="SSL Connection Error",
                    severity="Medium",
                    description=f"Could not establish SSL connection.",
                    evidence=str(e),
                    url=self.base_url
                ))

    async def run_full_scan(self):
        print(f"{Fore.BLUE}[+] Starting Advanced Scan on {self.base_url}{Style.RESET_ALL}")
        
        await asyncio.gather(
            self.detect_technology(),
            self.check_http_methods(),
            self.check_headers(),
            self.check_sql_injection(),
            self.check_xss(),
            self.check_open_redirect(),
            self.check_common_files(),
            self.check_ssl_details()
        )
        
        return self.vulnerabilities

async def main():
    target = input("Enter the website URL (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "https://" + target
        
    async with AdvancedVulnScanner(target) as scanner:
        vulns = await scanner.run_full_scan()
        
        print(f"\n{Fore.WHITE}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan Complete. Found {len(vulns)} vulnerabilities.{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'='*60}{Style.RESET_ALL}\n")
        
        if vulns:
            severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            vulns.sort(key=lambda x: severity_order.get(x.severity, 0), reverse=True)
            
            for v in vulns:
                print(v)
        else:
            print(f"{Fore.GREEN}[+] No common vulnerabilities detected.{Style.RESET_ALL}")

        # Wait for user to press Enter before closing
        input(f"\n{Fore.BLUE}[+] Press Enter to close...{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())