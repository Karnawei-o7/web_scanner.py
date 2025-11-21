#!/usr/bin/env python3
"""
Web Security Scanner GUI
For Educational and Authorized Testing Only
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import socket
import threading
import dns.resolver
import whois
import ssl
import urllib3
import time
import json
import csv
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Security Scanner v2.0 - Educational Use Only")
        self.root.geometry("900x700")
        
        # Security settings
        self.scanning = False
        self.current_scan_thread = None
        self.rate_limit_delay = 1  # seconds between requests
        self.vulnerabilities_found = []
        
        self.setup_gui()
        self.setup_menu()
        
    def setup_menu(self):
        """Add menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results", command=self.export_results_advanced)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def show_about(self):
        """About window"""
        messagebox.showinfo("About", 
                       "Web Security Scanner v2.0\n"
                       "For Educational Purposes Only\n"
                       "Use only on websites you own or have permission to test")
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Web Security Scanner v2.0", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # URL Input
        ttk.Label(main_frame, text="Target URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=70)
        self.url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.url_entry.insert(0, "https://")
        
        # Scan Options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.sql_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.headers_var = tk.BooleanVar(value=True)
        self.ports_var = tk.BooleanVar(value=True)
        self.info_var = tk.BooleanVar(value=True)
        self.files_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="SQL Injection", variable=self.sql_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="XSS Vulnerabilities", variable=self.xss_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Security Headers", variable=self.headers_var).grid(row=0, column=2, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Port Scanning", variable=self.ports_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Website Info", variable=self.info_var).grid(row=1, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Sensitive Files", variable=self.files_var).grid(row=1, column=2, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Results", command=self.export_results_advanced).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=5, column=0, columnspan=2, pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=85, height=25, bg='#1e1e1e', fg='white')
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
    def log(self, message):
        """Add message to results text"""
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.root.update()
        
    def update_status(self, message):
        """Update status label"""
        self.status_var.set(message)
        self.root.update_idletasks()
        
    def clear_results(self):
        """Clear results text"""
        self.results_text.delete(1.0, tk.END)
        
    def export_results_advanced(self):
        """Export results to multiple formats"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text", "*.txt"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                content = self.results_text.get(1.0, tk.END)
                
                if file_path.endswith('.json'):
                    report_data = {
                        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "target": self.url_entry.get(),
                        "results": content,
                        "vulnerabilities_found": self.vulnerabilities_found
                    }
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(report_data, f, indent=2, ensure_ascii=False)
                
                elif file_path.endswith('.csv'):
                    with open(file_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Scan Date", "Target", "Results"])
                        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), 
                                       self.url_entry.get(), content])
                
                else:  # txt format
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                
                messagebox.showinfo("Success", f"Results exported to {file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
    
    def start_scan(self):
        """Start the security scan"""
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
            
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showerror("Error", "Please enter a valid URL")
            return
        
        # Ask for confirmation for comprehensive scan
        enabled_scans = sum([self.sql_var.get(), self.xss_var.get(), 
                           self.ports_var.get(), self.headers_var.get(), 
                           self.files_var.get()])
        
        if enabled_scans >= 4:
            if not messagebox.askyesno("Comprehensive Scan", 
                "This comprehensive scan may take several minutes. Continue?"):
                return
        
        # Disable scan button during scan
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.progress.start()
        self.clear_results()
        self.update_status("Scanning in progress...")
        
        # Start scan in thread
        thread = threading.Thread(target=self.run_scan, args=(url,))
        thread.daemon = True
        thread.start()
        
    def run_scan(self, url):
        """Run the security scan"""
        try:
            self.scanning = True
            self.vulnerabilities_found = []
            
            self.log("=" * 60)
            self.log("WEB SECURITY SCAN STARTED")
            self.log("=" * 60)
            self.log(f"Target: {url}")
            self.log(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            self.log("")
            
            # Test if target is reachable
            self.update_status("Testing target availability...")
            try:
                test_response = requests.get(url, timeout=10, verify=False)
                self.log(f"✅ Target is reachable (Status: {test_response.status_code})")
            except Exception as e:
                self.log(f"❌ Target is not reachable: {e}")
                return

            # Run selected scans
            if self.headers_var.get():
                self.update_status("Scanning security headers...")
                self.scan_security_headers(url)
                
            if self.sql_var.get():
                self.update_status("Scanning for SQL injection...")
                self.scan_sql_injection(url)
                
            if self.xss_var.get():
                self.update_status("Scanning for XSS vulnerabilities...")
                self.scan_xss(url)
                
            if self.ports_var.get():
                self.update_status("Scanning open ports...")
                parsed_url = urlparse(url)
                self.scan_ports(parsed_url.netloc)
                
            if self.info_var.get():
                self.update_status("Gathering website information...")
                parsed_url = urlparse(url)
                self.scan_website_info(parsed_url.netloc)
            
            if self.files_var.get():
                self.update_status("Scanning for sensitive files...")
                self.scan_sensitive_files(url)
            
            # Summary
            self.log("\n" + "=" * 60)
            self.log("SCAN COMPLETED")
            self.log("=" * 60)
            self.log(f"Total vulnerabilities found: {len(self.vulnerabilities_found)}")
            
            if self.vulnerabilities_found:
                self.log("\nFound vulnerabilities:")
                for i, vuln in enumerate(self.vulnerabilities_found, 1):
                    self.log(f"  {i}. {vuln}")
            else:
                self.log("✅ No critical vulnerabilities found")
            
        except Exception as e:
            self.log(f"❌ SCAN ERROR: {e}")
        finally:
            self.scanning = False
            self.progress.stop()
            self.scan_button.config(state='normal')
            self.update_status("Scan completed")
            
    def scan_security_headers(self, url):
        """Scan for security headers"""
        self.log("\n[SECURITY HEADERS SCAN]")
        self.log("-" * 40)
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Content security policy',
                'X-XSS-Protection': 'XSS protection',
                'Referrer-Policy': 'Referrer policy control',
                'Permissions-Policy': 'Browser features control'
            }
            
            missing_headers = []
            
            for header, description in security_headers.items():
                if header in headers:
                    self.log(f"✅ {header}: {headers[header]}")
                else:
                    self.log(f"❌ {header}: MISSING - {description}")
                    missing_headers.append(header)
                    
            if missing_headers:
                self.vulnerabilities_found.append(f"Missing security headers: {', '.join(missing_headers)}")
                
        except Exception as e:
            self.log(f"❌ Failed to scan headers: {e}")
            
    def scan_sql_injection(self, url):
        """Scan for SQL Injection vulnerabilities"""
        self.log("\n[SQL INJECTION SCAN]")
        self.log("-" * 40)
        
        # Enhanced payload database
        payloads = [
            "'", "''", "`", "``", "\"", "\"\"",
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
            "' UNION SELECT 1,2,3--", 
            "'; DROP TABLE users--",
            "' AND 1=1--", "' AND 1=2--"
        ]
        
        params = ["id", "user", "product", "category", "page", "search", "query"]
        
        vulnerabilities_found = 0
        tested_count = 0
        
        for param in params:
            for payload in payloads:
                try:
                    tested_count += 1
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    sql_errors = [
                        "sql", "SQL", "database", "mysql", "syntax",
                        "query", "column", "table", "ORA-", "Microsoft OLE DB",
                        "warning", "error", "exception", "stack trace"
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.log(f"🚨 SQL Injection: {param} = {payload}")
                            vulnerabilities_found += 1
                            self.vulnerabilities_found.append(f"SQLi: {param}={payload}")
                            break
                    
                    # Rate limiting
                    time.sleep(0.2)
                            
                except Exception as e:
                    pass
                    
        self.log(f"📊 Tested {tested_count} payloads")
        
        if vulnerabilities_found == 0:
            self.log("✅ No SQL injection vulnerabilities detected")
        else:
            self.log(f"🔍 Found {vulnerabilities_found} potential SQLi vulnerabilities")
            
    def scan_xss(self, url):
        """Scan for XSS vulnerabilities"""
        self.log("\n[XSS SCAN]")
        self.log("-" * 40)
        
        test_params = ["q", "search", "name", "message", "comment", "input", "text"]
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        vulnerabilities_found = 0
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    if payload in response.text:
                        self.log(f"🚨 XSS Vulnerability: {param}")
                        vulnerabilities_found += 1
                        self.vulnerabilities_found.append(f"XSS: {param}")
                        break
                    
                    time.sleep(0.2)
                        
                except:
                    pass
                
        if vulnerabilities_found == 0:
            self.log("✅ No XSS vulnerabilities detected")
        else:
            self.log(f"🔍 Found {vulnerabilities_found} XSS vulnerabilities")
            
    def scan_ports(self, domain):
        """Scan common ports"""
        self.log("\n[PORT SCAN]")
        self.log("-" * 40)
        
        common_ports = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            3389: "RDP"
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                
                if result == 0:
                    self.log(f"🔓 {service} (Port {port}): OPEN")
                    open_ports.append(port)
                    self.vulnerabilities_found.append(f"Open port: {service} ({port})")
                sock.close()
                
            except:
                pass
                
        if not open_ports:
            self.log("✅ No unexpected open ports found")
        else:
            self.log(f"🔍 Found {len(open_ports)} open ports")
            
    def scan_website_info(self, domain):
        """Gather website information"""
        self.log("\n[WEBSITE INFORMATION]")
        self.log("-" * 40)
        
        try:
            # WHOIS information
            self.log("WHOIS Information:")
            domain_info = whois.whois(domain)
            self.log(f"  Registrar: {domain_info.registrar}")
            self.log(f"  Creation Date: {domain_info.creation_date}")
            self.log(f"  Expiration Date: {domain_info.expiration_date}")
            
        except:
            self.log("  ❌ Could not retrieve WHOIS information")
            
        try:
            # DNS information
            self.log("\nDNS Records:")
            record_types = ['A', 'MX', 'TXT', 'NS']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        self.log(f"  {record_type}: {rdata}")
                except:
                    pass
                    
        except:
            self.log("  ❌ Could not retrieve DNS information")
            
        try:
            # SSL certificate info
            self.log("\nSSL Certificate:")
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    self.log(f"  Issuer: {issuer.get('organizationName', 'Unknown')}")
                    self.log(f"  Valid Until: {cert['notAfter']}")
                    
        except:
            self.log("  ❌ Could not retrieve SSL information")

    def scan_sensitive_files(self, url):
        """Scan for sensitive files and leaks"""
        self.log("\n[SENSITIVE FILES SCAN]")
        self.log("-" * 40)
        
        sensitive_files = [
            "/.git/config", "/.env", "/.htaccess", "/web.config",
            "/backup.zip", "/dump.sql", "/config.php", "/admin.php",
            "/phpinfo.php", "/.DS_Store", "/robots.txt", "/sitemap.xml",
            "/wp-config.php", "/config.json", "/.aws/credentials"
        ]
        
        found_files = []
        
        for file_path in sensitive_files:
            try:
                test_url = urljoin(url, file_path)
                response = requests.get(test_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    self.log(f"🔍 Found: {test_url} (Status: {response.status_code})")
                    found_files.append(test_url)
                    self.vulnerabilities_found.append(f"Sensitive file: {test_url}")
                        
            except:
                pass
        
        if not found_files:
            self.log("✅ No sensitive files exposed")
        else:
            self.log(f"📁 Found {len(found_files)} sensitive files")

def main():
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
