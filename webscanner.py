import argparse
import requests
import socket
import ssl
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
from colorama import Fore, Style, init
import sys
import time
import threading 

# Initial color setup
init(autoreset=True)
BANNER = f"""
{Fore.RED}
▓█████▄  ▄▄▄       ██▓███   ██░ ██  ▒█████   ██▓███  
▒██▀ ██▌▒████▄    ▓██░  ██▒▓██░ ██▒▒██▒  ██▒▓██░  ██▒
░██   █▌▒██  ▀█▄  ▓██░ ██▓▒▒██▀▀██░▒██░  ██▒▓██░ ██▓▒
░▓█▄   ▌░██▄▄▄▄██ ▒██▄█▓▒ ▒░▓█ ░██ ▒██   ██░▒██▄█▓▒ ▒
░▒████▓  ▓█   ▓██▒▒██▒ ░  ░░▓█▒░██▓░ ████▓▒░▒██▒ ░  ░
 ▒▒▓  ▒  ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒▓▒░ ░  ░
 ░ ▒  ▒   ▒   ▒▒ ░░▒ ░      ▒ ░▒░ ░  ░ ▒ ▒░ ░▒ ░     
 ░ ░  ░   ░   ▒   ░░        ░  ░░ ░░ ░ ░ ▒  ░░       
   ░          ░  ░          ░  ░  ░    ░ ░           
 ░                                                    
{Fore.BLUE}      [ Web Vulnerability Scanner Pro ]
{Fore.YELLOW}         [ Version 3.14 - Kali Edition ]
{Style.RESET_ALL}
"""

class ScannerPro:
    def __init__(self, target, proxy=None, threads=20, wordlist=None, output=None, user_agent=None):
        self.target = self.normalize_url(target)
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.threads = threads
        self.wordlist = wordlist
        self.output = output
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'})
        self.vulnerabilities = []
        self.discovered_paths = set()
        self.lock = threading.Lock()
        self.start_time = time.time()

    @staticmethod
    def normalize_url(url):
        if not url.startswith(('http://', 'https://')):
            return f'http://{url}'
        return url

    def print_status(self, message):
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")

    def print_success(self, message):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")

    def print_warning(self, message):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

    def print_error(self, message):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")

    def crawl(self):
        """Advanced crawling with form and JavaScript detection"""
        try:
            response = self.session.get(self.target, proxies=self.proxy, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Traditional links
            for link in soup.find_all(['a', 'link'], href=True):
                self.process_link(link['href'])
            
            # JavaScript and CSS resources
            for resource in soup.find_all(['script', 'img', 'iframe'], src=True):
                self.process_link(resource['src'])
            
            # Forms
            for form in soup.find_all('form'):
                self.test_form(form)
            
        except Exception as e:
            self.print_error(f"Crawling error: {str(e)}")

    def process_link(self, url):
        full_url = urljoin(self.target, url)
        if full_url not in self.discovered_paths and self.target in full_url:
            self.discovered_paths.add(full_url)
            self.links_queue.put(full_url)

    def test_form(self, form):
        """Analyzes forms for CSRF, SQLi, and XSS"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = {inp.get('name'): inp.get('value', '') for inp in form.find_all('input')}
        
        # CSRF Detection
        if not any(name.lower() in ['csrf_token', 'authenticity_token'] for name in inputs):
            self.report_vulnerability('CSRF Potential', form_details=str(form))
        
        # Injection tests
        self.test_parameters(urljoin(self.target, action), method, inputs)

    def test_parameters(self, url, method, params):
        """Tests parameters for multiple vulnerabilities"""
        payloads = {
            'SQLi': ["'", "' OR '1'='1", "'; DROP TABLE users--"],
            'XSS': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'CMD': ["; ls", "| cat /etc/passwd", "`whoami`"]
        }
        
        for vuln_type, payload_list in payloads.items():
            for payload in payload_list:
                test_params = {k: f"{v}{payload}" for k, v in params.items()}
                try:
                    if method == 'post':
                        response = self.session.post(url, data=test_params, proxies=self.proxy)
                    else:
                        response = self.session.get(url, params=test_params, proxies=self.proxy)
                    
                    detection_patterns = {
                        'SQLi': r"(SQL syntax|unclosed quotation)",
                        'XSS': r"(<script>alert\(1\)</script>|onerror=alert\(1\))",
                        'CMD': r"(root:|www-data|bin/bash)"
                    }
                    
                    if re.search(detection_patterns[vuln_type], response.text, re.IGNORECASE):
                        self.report_vulnerability(vuln_type, url=url, payload=payload)
                        
                except Exception as e:
                    pass

    def check_ssl(self):
        """Analyzes SSL/TLS certificate"""
        hostname = urlparse(self.target).hostname
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Validate certificate
                    if not cert:
                        self.report_vulnerability('SSL Error', details="No certificate found")
                    
                    # Check expiration
                    ssl_info = ssl.get_server_certificate((hostname, 443))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ssl_info)
                    expiration_date = x509.get_notAfter().decode('utf-8')
                    self.print_status(f"Certificate valid until: {expiration_date}")
                    
        except Exception as e:
            self.report_vulnerability('SSL Error', details=str(e))

    def check_security_headers(self):
        """Checks critical security headers"""
        headers_to_check = {
            'Content-Security-Policy': 'missing',
            'X-Content-Type-Options': 'missing',
            'Strict-Transport-Security': 'missing',
            'X-Frame-Options': 'missing'
        }
        
        try:
            response = self.session.get(self.target, proxies=self.proxy)
            for header in headers_to_check:
                if header not in response.headers:
                    self.report_vulnerability('Security Header Missing', header=header)
                else:
                    headers_to_check[header] = 'present'
            
            self.print_status("Security Headers:")
            for header, status in headers_to_check.items():
                color = Fore.GREEN if status == 'present' else Fore.RED
                print(f"  {color}{header}: {status}{Style.RESET_ALL}")
                
        except Exception as e:
            self.print_error(f"Error checking headers: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}Web Vulnerability Scanner Pro{Style.RESET_ALL}"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    args = parser.parse_args()
    
    scanner = ScannerPro(target=args.target)
    
    try:
        scanner.start_scan()
    except KeyboardInterrupt:
        scanner.print_error("Scan interrupted by user!")
        sys.exit(1)
