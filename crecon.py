#!/usr/bin/env python3

import os
import sys
import json
import socket
import requests
import time
from urllib.parse import urljoin
import dns.resolver
import dns.query
import dns.exception
import whois
import nmap
from bs4 import BeautifulSoup, Comment
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import re
from datetime import datetime
import threading
import base64
import hashlib

try:
    from fake_useragent import UserAgent
    _UA = UserAgent()
except Exception:
    _UA = None

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def show_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗        ║
║   ██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║        ║
║   ██║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║        ║
║   ██║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║        ║
║   ╚██████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║        ║
║    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝        ║
║                                                               ║
║     🛡️ ADVANCE RECONNAISSANCE SUITE BY TREMOR v1.1 🛡️          ║
║              AI-Powered Security Analysis Tool               ║
║                                                               ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}[!] LEGAL DISCLAIMER: For authorized security testing only!{Colors.END}
{Colors.RED}[!] Unauthorized use may violate laws in your jurisdiction.{Colors.END}
"""
    print(banner)

def print_success(msg): print(f"{Colors.GREEN}[+] {msg}{Colors.END}")
def print_error(msg):   print(f"{Colors.RED}[-] {msg}{Colors.END}")
def print_warning(msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.END}")
def print_info(msg):    print(f"{Colors.BLUE}[*] {msg}{Colors.END}")
def print_banner_msg(msg): print(f"{Colors.CYAN}{Colors.BOLD}[~] {msg}{Colors.END}")

class CyberReconPro:
    def __init__(self, target, stealth_mode=False, output_dir="reports", verify_tls=False):
        self.target = target.strip()
        self.stealth_mode = stealth_mode
        self.output_dir = output_dir
        self.verify_tls = verify_tls  # note: default False to match original pattern where verify=False used
        self.results = {}
        self.session = requests.Session()
        self._set_default_headers()
        os.makedirs(output_dir, exist_ok=True)
        if not self.validate_target():
            print_error(f"Invalid target: {target}")
            sys.exit(1)

    def _set_default_headers(self):  
        ua = None  
        if _UA:  
            try:  
                ua = _UA.random  
            except Exception:  
                ua = None  
        if not ua:  
            ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36"  
        self.session.headers.update({'User-Agent': ua})  

    def get_headers(self):  
        if self.stealth_mode:  
            return {  
                'User-Agent': self.session.headers.get('User-Agent'),  
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',  
                'Accept-Language': 'en-US,en;q=0.5',  
                'Accept-Encoding': 'gzip, deflate',  
                'Connection': 'keep-alive',  
            }  
        return {'User-Agent': self.session.headers.get('User-Agent')}  

    def validate_target(self):  
        try:  
            socket.inet_aton(self.target)  
            return True  
        except Exception:  
            try:  
                socket.inet_pton(socket.AF_INET6, self.target)  
                return True  
            except Exception:  
                if len(self.target) == 0 or len(self.target) > 253:  
                    return False  
                if re.match(r'^[A-Za-z0-9.-]+$', self.target):  
                    try:  
                        socket.gethostbyname(self.target)  
                        return True  
                    except Exception:  
                        return False  
        return False  

    def advanced_dns_enumeration(self):  
        print_banner_msg("Performing Advanced DNS Enumeration...")  
        try:  
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']  
            dns_results = {}  
            resolver = dns.resolver.Resolver()  
            resolver.lifetime = 4  
            for record_type in record_types:  
                try:  
                    answers = resolver.resolve(self.target, record_type)  
                    dns_results[record_type] = [r.to_text() for r in answers]  
                    print_success(f"{record_type}: {dns_results[record_type]}")  
                except Exception as e:  
                    dns_results[record_type] = f"Not found: {e}"  
                    print_warning(f"{record_type}: Not found")  

            try:  
                ns_answers = resolver.resolve(self.target, 'NS')  
                zone_xfr = {}  
                for ns in ns_answers:  
                    ns_host = str(ns.target).rstrip('.')  
                    try:  
                        axfr = dns.query.xfr(ns_host, self.target, timeout=10)  
                        zone_records = [r.to_text() for r in axfr]  
                        if zone_records:  
                            zone_xfr[ns_host] = zone_records  
                            print_success(f"Zone transfer possible from {ns_host} (records returned)")  
                        else:  
                            zone_xfr[ns_host] = "No records returned or transfer denied"  
                            print_warning(f"Zone transfer attempted to {ns_host} - denied/no records")  
                    except Exception as e:  
                        zone_xfr[ns_host] = f"Failed: {e}"  
                        print_warning(f"Zone transfer to {ns_host} failed: {e}")  
                dns_results['zone_transfer'] = zone_xfr  
            except Exception as e:  
                dns_results['zone_transfer'] = "No NS records or NS lookup failed"  
                print_warning("No NS records for zone transfer or NS lookup failed")  

            self.results['dns_enumeration'] = dns_results  
        except Exception as e:  
            print_error(f"DNS enumeration failed: {e}")  
            self.results['dns_enumeration'] = str(e)  

    def subdomain_enumeration(self):  
        print_banner_msg("Enumerating Subdomains...")  
        try:  
            subdomains = []  
            wordlist = [  
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',  
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',  
                'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',  
                'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',  
                'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'api',  
                'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',  
                'sip', 'dns2', 'cdn', 'stats', 'sms', 'tv', 'pay', 'image', 'search', 'apps',  
                'wap', 'my', 'svn', 'js', 'admin', 'en'  
            ]  
            def check_subdomain(sub):  
                full_domain = f"{sub}.{self.target}"  
                try:  
                    socket.gethostbyname(full_domain)  
                    return full_domain  
                except:  
                    return None  

            with ThreadPoolExecutor(max_workers=30) as executor:  
                futures = [executor.submit(check_subdomain, sub) for sub in wordlist]  
                for future in as_completed(futures):  
                    result = future.result()  
                    if result:  
                        subdomains.append(result)  
                        print_success(f"Found: {result}")  

            self.results['subdomains'] = subdomains  
            print_info(f"Total subdomains found: {len(subdomains)}")  
        except Exception as e:  
            print_error(f"Subdomain enumeration failed: {e}")  
            self.results['subdomains'] = str(e)  

    def advanced_port_scan(self):  
        print_banner_msg("Performing Advanced Port Scan...")  
        try:  
            nm = nmap.PortScanner()  
            if self.stealth_mode:  
                scan_args = '-sS -T2 -f --randomize-hosts'  
                print_info("Using stealth scan configuration")  
            else:  
                scan_args = '-sS -sV -sC -O -T4'  
                print_info("Using aggressive scan configuration")  

            port_range = '1-10000'  
            print_info(f"Scanning ports {port_range}...")  
            nm.scan(self.target, port_range, arguments=scan_args)  

            open_ports = []  
            os_info = "Unable to detect"  
            hostname = ""  
            for host in nm.all_hosts():  
                hostname = nm[host].hostname() if hasattr(nm[host], 'hostname') else ''  
                for proto in nm[host].all_protocols():  
                    ports = list(nm[host][proto].keys())  
                    for port in ports:  
                        service = nm[host][proto][port]  
                        port_info = {  
                            'port': port,  
                            'protocol': proto,  
                            'state': service.get('state', ''),  
                            'service': service.get('name', ''),  
                            'version': service.get('version', ''),  
                            'product': service.get('product', ''),  
                            'extra': service.get('extrainfo', ''),  
                            'cpe': service.get('cpe', '')  
                        }  
                        open_ports.append(port_info)  
                        print_success(f"Port {port}/{proto} - {service.get('name','')} - {service.get('state','')}")  

                try:  
                    if 'osmatch' in nm[host] and nm[host]['osmatch']:  
                        os_info = nm[host]['osmatch'][0]['name']  
                        print_success(f"OS Detection: {os_info}")  
                except Exception:  
                    os_info = "Unable to detect"  
                    print_warning("OS detection failed")  

            self.results['port_scan'] = {  
                'open_ports': open_ports,  
                'os_detection': os_info,  
                'hostname': hostname  
            }  
            print_info(f"Scan completed: {len(open_ports)} open ports found")  
        except Exception as e:  
            print_error(f"Port scan failed: {e}")  
            self.results['port_scan'] = str(e)  

    def vulnerability_assessment(self):  
        print_banner_msg("Running Vulnerability Assessment...")  
        try:  
            vuln_findings = []  
            headers = self.get_headers()  
            try:  
                response = requests.get(f"http://{self.target}", headers=headers, timeout=10, verify=self.verify_tls)  
            except Exception:  
                response = requests.get(f"https://{self.target}", headers=headers, timeout=10, verify=self.verify_tls)  

            security_headers = {  
                'X-Frame-Options': 'Clickjacking protection',  
                'X-Content-Type-Options': 'MIME sniffing protection',  
                'X-XSS-Protection': 'XSS protection',  
                'Strict-Transport-Security': 'HSTS enforcement',  
                'Content-Security-Policy': 'CSP protection'  
            }  
            missing_headers = []  
            for header, description in security_headers.items():  
                if header not in response.headers:  
                    missing_headers.append(f"{header} - {description}")  
                    vuln_findings.append({  
                        'type': 'Missing Security Header',  
                        'severity': 'Medium',  
                        'description': f"Missing {header} header",  
                        'recommendation': f'Implement {header} header'  
                    })  
                    print_warning(f"Missing security header: {header}")  

            sensitive_patterns = [  
                r'password\s*[:=]\s*["\'][^"\']+["\']',  
                r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',  
                r'secret\s*[:=]\s*["\'][^"\']+["\']',  
                r'token\s*[:=]\s*["\'][^"\']+["\']'  
            ]  
            for pattern in sensitive_patterns:  
                if re.search(pattern, response.text, re.IGNORECASE):  
                    vuln_findings.append({  
                        'type': 'Exposed Credentials',  
                        'severity': 'High',  
                        'description': 'Potential credentials found in source code',  
                        'recommendation': 'Remove hardcoded credentials'  
                    })  
                    print_error("Potential credentials exposed in source code!")  
                    break  

            if not vuln_findings:  
                print_success("No major vulnerabilities detected")  
            else:  
                print_warning(f"Found {len(vuln_findings)} potential vulnerabilities")  

            self.results['vulnerability_assessment'] = vuln_findings  
        except Exception as e:  
            print_error(f"Vulnerability assessment failed: {e}")  
            self.results['vulnerability_assessment'] = str(e)  

    def advanced_web_crawler(self):  
        print_banner_msg("Advanced Web Crawling...")  
        try:  
            headers = self.get_headers()  
            try:  
                response = requests.get(f"http://{self.target}", headers=headers, timeout=10, verify=self.verify_tls)  
            except Exception:  
                response = requests.get(f"https://{self.target}", headers=headers, timeout=10, verify=self.verify_tls)  

            soup = BeautifulSoup(response.content, 'html.parser')  
            crawl_results = {'links': [], 'forms': [], 'scripts': [], 'emails': [], 'comments': []}  

            for link in soup.find_all('a', href=True):  
                href = link['href']  
                full_url = urljoin(f"http://{self.target}", href)  
                crawl_results['links'].append({'text': link.get_text(strip=True), 'url': full_url})  

            for form in soup.find_all('form'):  
                form_info = {'action': form.get('action', ''), 'method': form.get('method', 'get').upper(), 'inputs': []}  
                for input_tag in form.find_all(['input', 'textarea', 'select']):  
                    input_info = {'type': input_tag.get('type', 'text'), 'name': input_tag.get('name', ''), 'id': input_tag.get('id', '')}  
                    form_info['inputs'].append(input_info)  
                crawl_results['forms'].append(form_info)  

            for script in soup.find_all('script', src=True):  
                crawl_results['scripts'].append(urljoin(f"http://{self.target}", script['src']))  

            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  
            emails = re.findall(email_pattern, response.text)  
            crawl_results['emails'] = list(set(emails))  

            comments = []  
            for element in soup.find_all(string=lambda text: isinstance(text, Comment)):  
                txt = element.strip()  
                if txt:  
                    comments.append(txt)  
            crawl_results['comments'] = comments  

            self.results['web_crawl'] = crawl_results  
            print_success(f"Links: {len(crawl_results['links'])} | Forms: {len(crawl_results['forms'])} | Emails: {len(crawl_results['emails'])}")  
        except Exception as e:  
            print_error(f"Web crawling failed: {e}")  
            self.results['web_crawl'] = str(e)  

    def ssl_tls_analysis(self):  
        print_banner_msg("Analyzing SSL/TLS Configuration...")  
        try:  
            from cryptography import x509  
            from cryptography.hazmat.backends import default_backend  
            context = ssl.create_default_context()  
            with socket.create_connection((self.target, 443), timeout=10) as sock:  
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:  
                    cert_bin = ssock.getpeercert(True)  
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())  

                    def name_to_dict(name):  
                        out = {}  
                        for r in name.rdns:  
                            for attr in r:  
                                out[attr.oid._name] = attr.value  
                        return out  

                    cert_info = {  
                        'subject': name_to_dict(cert.subject),  
                        'issuer': name_to_dict(cert.issuer),  
                        'not_valid_before': cert.not_valid_before.isoformat(),  
                        'not_valid_after': cert.not_valid_after.isoformat(),  
                        'serial_number': str(cert.serial_number),  
                        'signature_algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)  
                    }  
                    now = datetime.utcnow()  
                    expires_in = (cert.not_valid_after - now).days  
                    cert_info['days_until_expiry'] = expires_in  
                    if expires_in < 30:  
                        cert_info['expiry_warning'] = f"Certificate expires in {expires_in} days"  
                        print_error(f"SSL Certificate expires in {expires_in} days!")  
                    else:  
                        print_success(f"SSL Certificate valid for {expires_in} days")  
                    self.results['ssl_analysis'] = cert_info  
        except Exception as e:  
            print_error(f"SSL analysis failed: {e}")  
            self.results['ssl_analysis'] = str(e)  

    def waf_detection(self):  
        print_banner_msg("Detecting WAF...")  
        try:  
            wafs = {  
                'Cloudflare': ['cloudflare', 'cf-ray'],  
                'Cloudfront': ['cloudfront', 'x-amz-cf-id'],  
                'Akamai': ['akamai', 'x-akamai'],  
                'Sucuri': ['sucuri', 'x-sucuri-id'],  
                'Incapsula': ['incapsula', 'x-iid'],  
                'ModSecurity': ['mod_security', 'modsecurity']  
            }  
            headers = self.get_headers()  
            try:  
                response = requests.get(f"http://{self.target}", headers=headers, timeout=10, verify=self.verify_tls)  
            except Exception:  
                response = requests.get(f"https://{self.target}", headers=headers, timeout=10, verify=self.verify_tls)  

            detected_waf = "Not detected"  
            resp_headers_lower = {k.lower(): v for k, v in response.headers.items()}  
            for waf_name, indicators in wafs.items():  
                for indicator in indicators:  
                    if any(indicator in k.lower() for k in resp_headers_lower.keys()) or any(indicator in str(v).lower() for v in resp_headers_lower.values()):  
                        detected_waf = waf_name  
                        print_warning(f"WAF Detected: {waf_name}")  
                        break  
                if detected_waf != "Not detected":  
                    break  

            if detected_waf == "Not detected":  
                print_success("No WAF detected")  
            self.results['waf_detection'] = detected_waf  
        except Exception as e:  
            print_error(f"WAF detection failed: {e}")  
            self.results['waf_detection'] = str(e)  

    def run_comprehensive_scan(self):  
        print_banner_msg(f"Starting Advanced Reconnaissance for: {self.target}")  
        print_info(f"Stealth Mode: {'ON' if self.stealth_mode else 'OFF'}")  
        print_info("Running modules concurrently...")  

        start_time = time.time()  
        modules = [  
            self.advanced_dns_enumeration,  
            self.subdomain_enumeration,  
            self.advanced_port_scan,  
            self.vulnerability_assessment,  
            self.advanced_web_crawler,  
            self.ssl_tls_analysis,  
            self.waf_detection  
        ]  

        with ThreadPoolExecutor(max_workers=6) as executor:  
            futures = [executor.submit(module) for module in modules]  
            for future in as_completed(futures):  
                try:  
                    future.result(timeout=300)  
                except Exception as e:  
                    print_error(f"Module execution error: {e}")  

        scan_duration = time.time() - start_time  
        self.results['scan_metadata'] = {  
            'target': self.target,  
            'timestamp': datetime.now().isoformat(),  
            'duration_seconds': round(scan_duration, 2),  
            'stealth_mode': self.stealth_mode  
        }  
        print_success(f"Advanced scan completed in {round(scan_duration, 2)} seconds")  
        return self.results  

    def generate_advanced_report(self):  
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  
        safe_target = re.sub(r'[^A-Za-z0-9_.-]', '_', self.target)  
        json_filename = f"{self.output_dir}/advanced_recon_{safe_target}_{timestamp}.json"  
        html_filename = f"{self.output_dir}/advanced_recon_{safe_target}_{timestamp}.html"  
        with open(json_filename, 'w') as f:  
            json.dump(self.results, f, indent=2, default=str)  
        self.generate_html_report(html_filename)  
        print_success(f"Advanced reports generated:")  
        print_info(f"JSON: {json_filename}")  
        print_info(f"HTML: {html_filename}")  
        return json_filename, html_filename  

    def generate_html_report(self, filename):  
        html_template = f"""  
        <!DOCTYPE html>  
        <html>  
        <head>  
            <title>CRECON Report - {self.target}</title>  
            <style>  
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0f0f0f; color: #00ff00; }}  
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #00ff00; background: #1a1a1a; }}  
                .vulnerability {{ background-color: #330000; padding: 10px; margin: 5px 0; border-left: 3px solid red; }}  
                .success {{ color: #00ff00; }}  
                .warning {{ color: #ffff00; }}  
                .error {{ color: #ff0000; }}  
                .banner {{ background: linear-gradient(45deg, #000, #00ff00); padding: 20px; text-align: center; color: white; }}  
            </style>  
        </head>  
        <body>  
            <div class="banner">  
                <h1>🛡️ CRECON Report</h1>  
                <h2>Target: {self.target}</h2>  
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>  
            </div>  
            <div class="section">  
                <h3>📊 Scan Summary</h3>  
                <p>Duration: {self.results.get('scan_metadata', {}).get('duration_seconds', 'N/A')} seconds</p>  
                <p>Stealth Mode: {'Enabled' if self.stealth_mode else 'Disabled'}</p>  
            </div>  
            <div class="section">  
                <h3>🔎 DNS</h3>  
                <pre>{json.dumps(self.results.get('dns_enumeration', {}), indent=2)}</pre>  
            </div>  
            <div class="section">  
                <h3>🌐 Subdomains</h3>  
                <pre>{json.dumps(self.results.get('subdomains', []), indent=2)}</pre>  
            </div>  
            <!-- Additional sections can be expanded similarly -->  
        </body>  
        </html>  
        """  
        with open(filename, 'w') as f:  
            f.write(html_template)

def main():
    show_banner()
    parser = argparse.ArgumentParser(description='CRECON - Advanced Information Gathering')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--output', default='reports', help='Output directory')
    parser.add_argument('--no-verify', action='store_true', help='Do not verify TLS certificates (keeps original behavior when present)')
    args = parser.parse_args()

    if len(sys.argv) < 2:  
        parser.print_help()  
        sys.exit(1)  

    print(f"{Colors.RED}{Colors.BOLD}")  
    print("⚠️  LEGAL WARNING: This tool is for authorized penetration testing only!")  
    print("   Unauthorized use against systems you don't own is ILLEGAL.")  
    print(f"{Colors.END}")  

    confirm = input(f"{Colors.YELLOW}[?] Do you have permission to scan this target? (y/N): {Colors.END}")  
    if confirm.lower() not in ['y', 'yes']:  
        print(f"{Colors.RED}[-] Scan aborted. Proper authorization required.{Colors.END}")  
        sys.exit(1)  

    scanner = CyberReconPro(args.target, args.stealth, args.output, verify_tls=(not args.no_verify))  
    results = scanner.run_comprehensive_scan()  
    scanner.generate_advanced_report()  

    print(f"\n{Colors.GREEN}{Colors.BOLD}")  
    print("✅ ADVANCED RECONNAISSANCE COMPLETED!")  
    print(f"{Colors.END}")  
    print(f"{Colors.CYAN}📊 Reports generated in '{args.output}/' directory{Colors.END}")  
    print(f"{Colors.YELLOW}🔒 Remember: With great power comes great responsibility!{Colors.END}")

if __name__ == "__main__":
    main()
