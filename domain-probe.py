import sys
import importlib
import socket
import ssl
import re
from urllib.parse import urlparse, urljoin
import concurrent.futures
import json
from datetime import datetime
import time
import os
import tkinter as tk
from tkinter import messagebox, simpledialog

def check_imports():
    required_modules = {
        'whois': 'python-whois',
        'dns.resolver': 'dnspython',
        'requests': 'requests',
        'bs4': 'beautifulsoup4',
        'shodan': 'shodan',
        'sublist3r': 'sublist3r',
        'tld': 'tld'
    }
    
    missing_modules = []
    
    for module, package in required_modules.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing_modules.append(f"{package}")
    
    if missing_modules:
        print("The following required packages are missing:")
        for package in missing_modules:
            print(f"  - {package}")
        print("\nPlease install them using:")
        print(f"pip install {' '.join(missing_modules)}")
        sys.exit(1)

check_imports()

import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import shodan
import sublist3r
from tld import get_tld

def get_shodan_key():
    if os.path.exists('shodankey.json'):
        with open('shodankey.json', 'r') as f:
            data = json.load(f)
            return data.get('key')
    else:
        root = tk.Tk()
        root.withdraw()
        has_key = messagebox.askyesno("Shodan API Key", "Do you have a Shodan API key?")
        if has_key:
            key = simpledialog.askstring("Shodan API Key", "Please enter your Shodan API key:")
            if key:
                with open('shodankey.json', 'w') as f:
                    json.dump({'key': key}, f)
                return key
        else:
            with open('shodankey.json', 'w') as f:
                json.dump({'key': None}, f)
    return None

SHODAN_API_KEY = get_shodan_key()

def get_subdomains(domain):
    print("\nDiscovering subdomains...")
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

def check_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return f"{subdomain} ({ip})"
    except socket.gaierror:
        return None

def detect_waf(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        waf_detected = []
        if "cloudflare" in response.headers.get('Server', '').lower():
            waf_detected.append("Cloudflare")
        if "x-sucuri-id" in response.headers:
            waf_detected.append("Sucuri")
        if "x-fw-protection" in response.headers:
            waf_detected.append("Wordfence")
        if "x-xss-protection" in response.headers:
            waf_detected.append("Generic XSS Protection")
        return waf_detected if waf_detected else ["No WAF detected"]
    except requests.RequestException:
        return ["Unable to detect WAF"]

def probe_website(domain):
    print(f"\nProbing website: {domain}")
    base_url = f"https://{domain}"
    interesting_findings = []

    def check_url(url, method='GET'):
        try:
            response = requests.request(method, url, timeout=10, allow_redirects=False)
            status = response.status_code
            print(f"  {method} {url} - Status: {status}")
            
            if status not in [403, 404, 405]:
                headers_info = []
                for header, value in response.headers.items():
                    if header.lower() not in ['date', 'content-type', 'content-length', 'connection', 'server']:
                        headers_info.append(f"{header}: {value}")
                
                if headers_info:
                    interesting_findings.append({
                        "url": url,
                        "method": method,
                        "status": status,
                        "headers": headers_info
                    })
                
                if method == 'GET' and status == 200:
                    content_sample = response.text[:1000].lower()
                    if any(keyword in content_sample for keyword in ['error', 'exception', 'warning', 'debug', 'stack trace']):
                        interesting_findings.append(f"Potential sensitive information in {url}")
            
            return status, response.headers
        except requests.RequestException as e:
            print(f"  Error checking {url}: {str(e)}")
            return None, None

    # Check root level files
    root_files = ['robots.txt', 'sitemap.xml', 'favicon.ico', '.well-known/security.txt', 'package.json']
    for file in root_files:
        check_url(urljoin(base_url, file))

    frameworks = {
        'Flask': [
            ('static/favicon.ico', 'Static file'),
            ('static/scripts.js', 'JavaScript file'),
            ('static/styles.css', 'CSS file'),                 
            ('static/css/style.css', 'CSS file'),
            ('static/css/styles.css', 'CSS file'),
            ('static/js/main.js', 'JavaScript file'),
            ('static/js/script.js', 'JavaScript file'),  
            ('static/js/scripts.js', 'JavaScript file'),   
            ('templates/index.html', 'Template file'),
            ('app.py', 'Main application file'),
            ('app/__init__.py', 'Flask application factory'),
            ('config.py', 'Configuration file'),
            ('wsgi.py', 'WSGI server configuration'),            
            ('requirements.txt', 'Python dependencies')
        ],
        'Django': [
            ('static/favicon.ico', 'Static file'),
            ('static/css/style.css', 'CSS file'),
            ('static/js/main.js', 'JavaScript file'),
            ('templates/base.html', 'Base template'),
            ('manage.py', 'Management script'),
            ('requirements.txt', 'Python dependencies')
        ],
        'Laravel': [
            ('public/favicon.ico', 'Favicon'),
            ('public/css/app.css', 'CSS file'),
            ('public/js/app.js', 'JavaScript file'),
            ('resources/views/welcome.blade.php', 'View file'),
            ('artisan', 'Artisan CLI'),
            ('composer.json', 'Composer dependencies')
        ],
        'WordPress': [
            ('wp-content/themes/index.php', 'Themes directory'),
            ('wp-content/plugins/index.php', 'Plugins directory'),
            ('wp-login.php', 'Login page'),
            ('wp-config.php', 'Configuration file'),
            ('wp-includes/version.php', 'Version information')
        ],
        'Joomla': [
            ('administrator/index.php', 'Admin login'),
            ('configuration.php', 'Configuration file'),
            ('templates/system/css/system.css', 'System CSS'),
            ('libraries/joomla/version.php', 'Version information')
        ],
        'Drupal': [
            ('sites/default/files', 'Default files directory'),
            ('core/misc/drupal.js', 'Core JavaScript'),
            ('core/install.php', 'Installation script'),
            ('sites/default/settings.php', 'Settings file')
        ],
        'Node.js': [
            ('package.json', 'Node.js project file'),
            ('server.js', 'Common server file'),
            ('app.js', 'Common application file'),
            ('index.js', 'Common entry point'),
            ('node_modules/', 'Node.js dependencies directory')
        ]
    }

    for framework, paths in frameworks.items():
        print(f"\nChecking for {framework} specific files:")
        framework_found = False
        for path, description in paths:
            status, _ = check_url(urljoin(base_url, path))
            if status == 200:
                interesting_findings.append(f"Possible {framework} framework detected: {path} ({description})")
                framework_found = True
        if framework_found:
            print(f"{framework} framework likely detected")

    # Check for common sensitive files
    sensitive_files = [
        '.git/HEAD', '.env', 'config.php', 'web.config', 'phpinfo.php',
        'error_log', 'debug.log', 'access.log', 'backup.sql', 'database.sql'
    ]
    print("\nChecking for sensitive files:")
    for file in sensitive_files:
        check_url(urljoin(base_url, file))

    # Check for API endpoints
    api_paths = ['api', 'api/v1', 'api/v2', 'graphql', 'swagger', 'swagger-ui.html', 'docs']
    print("\nChecking for API endpoints:")
    for path in api_paths:
        check_url(urljoin(base_url, path))

    # Check OPTIONS method for the main URL
    print("\nChecking OPTIONS method:")
    _, headers = check_url(base_url, method='OPTIONS')
    if headers:
        allowed_methods = headers.get('Allow')
        if allowed_methods:
            interesting_findings.append(f"Allowed Methods: {allowed_methods}")

    # Check security headers
    print("\nChecking for security headers:")
    security_headers = [
        'Strict-Transport-Security', 'Content-Security-Policy',
        'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
        'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy',
    ]
    _, headers = check_url(base_url)
    if headers:
        for header in security_headers:
            value = headers.get(header, 'Not set')
            print(f"  {header}: {value}")
            if value != 'Not set':
                interesting_findings.append(f"Security Header: {header}: {value}")

        # Check for sensitive headers
        print("\nChecking for sensitive headers:")
        sensitive_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in sensitive_headers:
            if header in headers:
                print(f"  {header}: {headers[header]}")
                interesting_findings.append(f"Sensitive Header: {header}: {headers[header]}")

    # Check for cookie security
    print("\nChecking for cookie security:")
    _, headers = check_url(base_url)
    if headers:
        cookies = headers.get('Set-Cookie')
        if cookies:
            for cookie in cookies.split(', '):
                cookie_name = cookie.split('=')[0]
                secure = 'Secure' in cookie
                httponly = 'HttpOnly' in cookie
                samesite = 'SameSite' in cookie
                print(f"  {cookie_name}:")
                print(f"    Secure: {secure}")
                print(f"    HttpOnly: {httponly}")
                print(f"    SameSite: {samesite}")
                cookie_info = f"Cookie {cookie_name}: Secure={secure}, HttpOnly={httponly}, SameSite={samesite}"
                interesting_findings.append(cookie_info)

    return interesting_findings

def shodan_scan(ip):
    if not SHODAN_API_KEY:
        print("\nShodan scan skipped: No API key provided")
        return []

    api = shodan.Shodan(SHODAN_API_KEY)
    shodan_info = []
    try:
        print("\nRetrieving Shodan information...")
        host = api.host(ip)
        
        print("\nShodan Information:")
        print(f"IP: {host.get('ip_str', 'N/A')}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        print(f"Country: {host.get('country_name', 'N/A')}")
        print(f"City: {host.get('city', 'N/A')}")
        
        shodan_info.extend([
            f"IP: {host.get('ip_str', 'N/A')}",
            f"Organization: {host.get('org', 'N/A')}",
            f"Operating System: {host.get('os', 'N/A')}",
            f"Country: {host.get('country_name', 'N/A')}",
            f"City: {host.get('city', 'N/A')}"
        ])
        
        print("\nOpen Ports:")
        for item in host.get('data', []):
            print(f"  Port {item['port']}:")
            print(f"    Service: {item.get('product', 'N/A')}")
            print(f"    Version: {item.get('version', 'N/A')}")
            print(f"    Banner: {item.get('data', 'N/A')[:100]}...")
            shodan_info.append(f"Open Port: {item['port']} - Service: {item.get('product', 'N/A')}")
        
        print("\nVulnerabilities:")
        for item in host.get('vulns', []):
            print(f"  {item}")
            shodan_info.append(f"Vulnerability: {item}")
        
    except shodan.APIError as e:
        print(f"Shodan Error: {e}")

    return shodan_info

def format_datetime(dt):
    if isinstance(dt, list):
        return [d.strftime("%Y-%m-%d %H:%M:%S") if d else "N/A" for d in dt]
    elif dt:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return "N/A"

def get_domain_info(domain):
    print(f"Gathering information for {domain}\n")
    report = {"Domain": domain, "Findings": []}

    try:
        w = whois.whois(domain)
        print("WHOIS Information:")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {format_datetime(w.creation_date)}")
        print(f"Expiration Date: {format_datetime(w.expiration_date)}")
        print(f"Name Servers: {w.name_servers}")
        print(f"Registrant: {w.registrant}")
        print(f"Admin: {w.admin}")
        print(f"Tech: {w.tech}")
        report["Findings"].extend([
            f"Registrar: {w.registrar}",
            f"Creation Date: {format_datetime(w.creation_date)}",
            f"Expiration Date: {format_datetime(w.expiration_date)}",
            f"Name Servers: {w.name_servers}"
        ])
    except Exception as e:
        print(f"Error retrieving WHOIS information: {str(e)}")

    print("\nDNS Information:")
    for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA', 'PTR']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"{record_type} Records:")
            for rdata in answers:
                print(f"  {rdata}")
                report["Findings"].append(f"{record_type} Record: {rdata}")
        except dns.resolver.NoAnswer:
            print(f"No {record_type} records found")
        except Exception as e:
            print(f"Error retrieving {record_type} records: {str(e)}")

    subdomains = get_subdomains(domain)
    if subdomains:
        print("\nDiscovered Subdomains:")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_subdomain, subdomains))
        valid_subdomains = [result for result in results if result]
        for subdomain in valid_subdomains:
            print(f"  {subdomain}")
            report["Findings"].append(f"Subdomain: {subdomain}")
    else:
        print("\nNo subdomains discovered.")

    try:
        ip = socket.gethostbyname(domain)
        print(f"\nIP Address: {ip}")
        report["Findings"].append(f"IP Address: {ip}")
        
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
            print(f"Reverse DNS: {reverse_dns}")
            report["Findings"].append(f"Reverse DNS: {reverse_dns}")
        except socket.herror:
            print("Reverse DNS: Not available")
        
        shodan_results = shodan_scan(ip)
        report["Findings"].extend(shodan_results)
        
    except socket.gaierror:
        print("\nUnable to resolve IP address")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        print("\nSSL Certificate Information:")
        print(f"Subject: {dict(x[0] for x in cert['subject'])}")
        print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
        print(f"Version: {cert['version']}")
        print(f"Serial Number: {cert['serialNumber']}")
        print(f"Not Before: {cert['notBefore']}")
        print(f"Not After: {cert['notAfter']}")
        print(f"OCSP: {cert.get('OCSP', 'Not available')}")
        print(f"Subject Alt Names: {cert.get('subjectAltName', 'Not available')}")
        report["Findings"].extend([
            f"SSL Cert Subject: {dict(x[0] for x in cert['subject'])}",
            f"SSL Cert Issuer: {dict(x[0] for x in cert['issuer'])}",
            f"SSL Cert Expiry: {cert['notAfter']}"
        ])
    except Exception as e:
        print(f"\nError retrieving SSL Certificate information: {str(e)}")

    successful_probes = probe_website(domain)
    report["Findings"].extend(successful_probes)

    print("\nAdditional Checks:")
    
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        print("DNSSEC: Enabled")
        report["Findings"].append("DNSSEC: Enabled")
    except Exception:
        print("DNSSEC: Not enabled or not properly configured")
    
    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        spf_record = next((r for r in spf if 'v=spf1' in str(r)), None)
        if spf_record:
            print(f"SPF Record: Found")
            report["Findings"].append(f"SPF Record: {spf_record}")
        else:
            print("SPF Record: Not found")
    except Exception as e:
        print(f"SPF Record: Unable to check - {str(e)}")
    
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_record = next((r for r in dmarc if 'v=DMARC1' in str(r)), None)
        if dmarc_record:
            print(f"DMARC Record: Found")
            report["Findings"].append(f"DMARC Record: {dmarc_record}")
        else:
            print("DMARC Record: Not found")
    except Exception as e:
        print(f"DMARC Record: Unable to check - {str(e)}")

    return report

def print_final_report(report):
    print("\n" + "="*50)
    print(f"FINAL REPORT FOR {report['Domain']}")
    print("="*50)
    print("\nInteresting Findings:")
    
    grouped_findings = {
        "Subdomains": [],
        "DNS Records": [],
        "SSL Certificate": [],
        "Interesting URLs": [],
        "Security Headers": [],
        "Sensitive Headers": [],
        "Cookies": [],
        "Framework Detection": [],          
        "Other": []
    }
    
    for finding in report['Findings']:
        if isinstance(finding, dict) and 'url' in finding:
            grouped_findings["Interesting URLs"].append(finding)
        elif finding.startswith("Subdomain:"):
            grouped_findings["Subdomains"].append(finding)
        elif any(record in finding for record in ['A Record:', 'AAAA Record:', 'MX Record:', 'NS Record:', 'TXT Record:', 'CNAME Record:', 'SOA Record:', 'SRV Record:', 'CAA Record:', 'PTR Record:']):
            grouped_findings["DNS Records"].append(finding)
        elif finding.startswith("SSL Cert"):
            grouped_findings["SSL Certificate"].append(finding)
        elif finding.startswith("Security Header:"):
            grouped_findings["Security Headers"].append(finding)
        elif finding.startswith("Sensitive Header:"):
            grouped_findings["Sensitive Headers"].append(finding)
        elif finding.startswith("Cookie"):
            grouped_findings["Cookies"].append(finding)
        elif finding.startswith("Possible") and "framework detected" in finding:
            grouped_findings["Framework Detection"].append(finding)            
        else:
            grouped_findings["Other"].append(finding)
    
    for group, findings in grouped_findings.items():
        if findings:
            print(f"\n{group}:")
            if group == "Interesting URLs":
                for finding in findings:
                    print(f"- {finding['method']} {finding['url']} - Status: {finding['status']}")
                    for header in finding['headers']:
                        print(f"  {header}")
            else:
                for finding in findings:
                    print(f"- {finding}")
    
    print("\n" + "="*50)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter the domain name (e.g., example.com): ")
    report = get_domain_info(domain)
    print_final_report(report)