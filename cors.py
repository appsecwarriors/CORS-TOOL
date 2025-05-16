#!/usr/bin/env python3
"""
CORS Vulnerability Tester with Burp Proxy Integration
Author: Security Engineer
Version: 2.0
"""

import requests
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from urllib.parse import urlparse
import json
import csv
import os
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class CORSTester:
    def __init__(self):
        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        self.default_headers = {
            'X-Custom-Header': 'test',
            'X-Requested-With': 'XMLHttpRequest'
        }
        self.proxies = None
        self.verify_ssl = False
        self.timeout = 15

    def test_cors(self, url, methods, headers, collaborator=None, custom_origin=None):
        results = {}
        origin = custom_origin if custom_origin else "https://evil.com"
        
        if collaborator:
            origin = f"http://{collaborator}"
        
        for method in methods:
            try:
                headers_to_send = {
                    'Origin': origin,
                    'Access-Control-Request-Method': method,
                    **headers
                }
                
                # Preflight request
                preflight_headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': method,
                    'Access-Control-Request-Headers': ','.join(headers.keys())
                }
                
                options_resp = requests.options(
                    url,
                    headers=preflight_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    allow_redirects=False
                )
                
                # Actual request
                if method == 'GET':
                    resp = requests.get(url, headers=headers_to_send, timeout=self.timeout, 
                                     verify=self.verify_ssl, proxies=self.proxies, allow_redirects=False)
                elif method == 'POST':
                    resp = requests.post(url, headers=headers_to_send, timeout=self.timeout, 
                                      verify=self.verify_ssl, proxies=self.proxies, allow_redirects=False)
                elif method == 'PUT':
                    resp = requests.put(url, headers=headers_to_send, timeout=self.timeout, 
                                     verify=self.verify_ssl, proxies=self.proxies, allow_redirects=False)
                elif method == 'DELETE':
                    resp = requests.delete(url, headers=headers_to_send, timeout=self.timeout, 
                                        verify=self.verify_ssl, proxies=self.proxies, allow_redirects=False)
                elif method == 'PATCH':
                    resp = requests.patch(url, headers=headers_to_send, timeout=self.timeout, 
                                        verify=self.verify_ssl, proxies=self.proxies, allow_redirects=False)
                elif method == 'HEAD':
                    resp = requests.head(url, headers=headers_to_send, timeout=self.timeout, 
                                      verify=self.verify_ssl, proxies=self.proxies, allow_redirects=False)
                elif method == 'OPTIONS':
                    resp = options_resp
                
                # Get CORS headers
                cors_headers = {
                    'ACAO': resp.headers.get('Access-Control-Allow-Origin', ''),
                    'ACAC': resp.headers.get('Access-Control-Allow-Credentials', ''),
                    'ACAM': resp.headers.get('Access-Control-Allow-Methods', ''),
                    'ACAH': resp.headers.get('Access-Control-Allow-Headers', ''),
                    'ACExH': resp.headers.get('Access-Control-Expose-Headers', '')
                }
                
                # Vulnerability assessment
                vuln_status = "Secure"
                notes = []
                
                if cors_headers['ACAO'] == '*':
                    if cors_headers['ACAC'] == 'true':
                        vuln_status = "CRITICAL: Wildcard with credentials"
                        notes.append("Wildcard ACAO with ACAC:true - full compromise possible")
                    else:
                        vuln_status = "VULNERABLE: Wildcard ACAO"
                        notes.append("Wildcard ACAO allows any origin to access resources")
                elif cors_headers['ACAO'] == origin:
                    if cors_headers['ACAC'] == 'true':
                        vuln_status = "CRITICAL: Origin reflection with credentials"
                        notes.append("Reflected origin with ACAC:true - full compromise possible")
                    else:
                        vuln_status = "VULNERABLE: Origin reflection"
                        notes.append("Origin reflection allows CSRF attacks")
                elif cors_headers['ACAO'] and ',' in cors_headers['ACAO']:
                    vuln_status = "VULNERABLE: Multiple ACAO values"
                    notes.append("Multiple ACAO values may be exploitable")
                
                if cors_headers['ACAC'] == 'true' and vuln_status == "Secure":
                    notes.append("ACAC:true but no vulnerable ACAO configuration")
                
                results[method] = {
                    'status_code': resp.status_code,
                    'cors_headers': cors_headers,
                    'vulnerability': vuln_status,
                    'response_time': resp.elapsed.total_seconds(),
                    'request_headers': headers_to_send,
                    'response_headers': dict(resp.headers),
                    'notes': notes,
                    'url': url,
                    'origin_used': origin,
                    'timestamp': datetime.now().isoformat()
                }
                
            except requests.exceptions.RequestException as e:
                results[method] = {
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
            except Exception as e:
                results[method] = {
                    'error': f"Unexpected error: {str(e)}",
                    'timestamp': datetime.now().isoformat()
                }
        
        return results

class CORSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CORS Vulnerability Tester v2.0 | Developed by AppSecWarrior")
        self.root.geometry("1000x800")
        self.tester = CORSTester()
        self.current_results = None
        
        # Configure styles
        self.configure_styles()
        self.create_widgets()
        
    def configure_styles(self):
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabel', padding=5)
        style.configure('Critical.Treeview', background='#ffcccc')
        style.configure('Vulnerable.Treeview', background='#fff3cd')
        style.configure('Warning.Treeview', background='#e7f4ff')
        style.configure('Secure.Treeview', background='#e8f5e9')
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel (configuration)
        left_panel = ttk.Frame(main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Right panel (results)
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Configuration panel widgets
        config_frame = ttk.LabelFrame(left_panel, text="Test Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=5)
        
        # URL
        ttk.Label(config_frame, text="Target URL:").pack(anchor=tk.W)
        self.url_entry = ttk.Entry(config_frame)
        self.url_entry.pack(fill=tk.X, pady=(0, 10))
        self.url_entry.insert(0, "https://example.com/api")
        
        # HTTP Methods
        methods_frame = ttk.LabelFrame(config_frame, text="HTTP Methods", padding=5)
        methods_frame.pack(fill=tk.X, pady=5)
        
        self.method_vars = {}
        for i, method in enumerate(self.tester.methods):
            self.method_vars[method] = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(methods_frame, text=method, variable=self.method_vars[method])
            cb.pack(side=tk.LEFT, padx=5)
        
        # Headers
        headers_frame = ttk.LabelFrame(config_frame, text="Custom Headers", padding=5)
        headers_frame.pack(fill=tk.X, pady=5)
        
        self.headers_text = scrolledtext.ScrolledText(headers_frame, height=5)
        self.headers_text.pack(fill=tk.X)
        self.headers_text.insert(tk.END, "\n".join([f"{k}:{v}" for k, v in self.tester.default_headers.items()]))
        
        # Advanced Options
        advanced_frame = ttk.LabelFrame(config_frame, text="Advanced Options", padding=5)
        advanced_frame.pack(fill=tk.X, pady=5)
        
        # Origin
        ttk.Label(advanced_frame, text="Custom Origin:").pack(anchor=tk.W)
        self.origin_entry = ttk.Entry(advanced_frame)
        self.origin_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Collaborator
        ttk.Label(advanced_frame, text="Burp Collaborator:").pack(anchor=tk.W)
        self.collab_entry = ttk.Entry(advanced_frame)
        self.collab_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Proxy Settings
        proxy_frame = ttk.Frame(advanced_frame)
        proxy_frame.pack(fill=tk.X, pady=5)
        
        self.use_proxy = tk.BooleanVar(value=False)
        proxy_cb = ttk.Checkbutton(proxy_frame, text="Use Burp Proxy", variable=self.use_proxy)
        proxy_cb.pack(side=tk.LEFT)
        
        ttk.Label(proxy_frame, text="Host:").pack(side=tk.LEFT, padx=(10, 2))
        self.proxy_host = ttk.Entry(proxy_frame, width=10)
        self.proxy_host.pack(side=tk.LEFT)
        self.proxy_host.insert(0, "127.0.0.1")
        
        ttk.Label(proxy_frame, text="Port:").pack(side=tk.LEFT, padx=(5, 2))
        self.proxy_port = ttk.Entry(proxy_frame, width=5)
        self.proxy_port.pack(side=tk.LEFT)
        self.proxy_port.insert(0, "8080")
        
        # SSL Verification
        self.verify_ssl = tk.BooleanVar(value=False)
        ssl_cb = ttk.Checkbutton(advanced_frame, text="Verify SSL", variable=self.verify_ssl)
        ssl_cb.pack(anchor=tk.W)
        
        # Timeout
        timeout_frame = ttk.Frame(advanced_frame)
        timeout_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(timeout_frame, text="Timeout (s):").pack(side=tk.LEFT)
        self.timeout_entry = ttk.Entry(timeout_frame, width=5)
        self.timeout_entry.pack(side=tk.LEFT, padx=5)
        self.timeout_entry.insert(0, "15")
        
        # Action Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        test_btn = ttk.Button(button_frame, text="Run Test", command=self.run_test)
        test_btn.pack(side=tk.LEFT, expand=True, padx=2)
        
        clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_results)
        clear_btn.pack(side=tk.LEFT, expand=True, padx=2)
        
        export_btn = ttk.Button(button_frame, text="Export", command=self.export_results)
        export_btn.pack(side=tk.LEFT, expand=True, padx=2)
        
        # Results panel widgets
        results_frame = ttk.LabelFrame(right_panel, text="Test Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results Treeview
        self.results_tree = ttk.Treeview(results_frame, columns=('Method', 'Status', 'ACAO', 'ACAC', 'Vulnerability', 'Time'), show='headings')
        
        self.results_tree.heading('Method', text='Method')
        self.results_tree.heading('Status', text='Status')
        self.results_tree.heading('ACAO', text='ACA-Origin')
        self.results_tree.heading('ACAC', text='ACA-Credentials')
        self.results_tree.heading('Vulnerability', text='Vulnerability')
        self.results_tree.heading('Time', text='Time(s)')
        
        self.results_tree.column('Method', width=70, anchor=tk.CENTER)
        self.results_tree.column('Status', width=70, anchor=tk.CENTER)
        self.results_tree.column('ACAO', width=150)
        self.results_tree.column('ACAC', width=100, anchor=tk.CENTER)
        self.results_tree.column('Vulnerability', width=250)
        self.results_tree.column('Time', width=70, anchor=tk.CENTER)
        
        self.results_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details panel
        details_frame = ttk.LabelFrame(right_panel, text="Details", padding=10)
        details_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=10)
        self.details_text.pack(fill=tk.BOTH)
        
        # Bind treeview selection
        self.results_tree.bind('<<TreeviewSelect>>', self.show_details)
    
    def run_test(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        selected_methods = [m for m, var in self.method_vars.items() if var.get()]
        if not selected_methods:
            messagebox.showerror("Error", "Please select at least one HTTP method")
            return
        
        # Get headers
        headers = {}
        headers_text = self.headers_text.get("1.0", tk.END).strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    header, value = line.split(':', 1)
                    headers[header.strip()] = value.strip()
        
        # Get advanced options
        collaborator = self.collab_entry.get().strip() or None
        custom_origin = self.origin_entry.get().strip() or None
        
        # Configure proxy
        if self.use_proxy.get():
            proxy_host = self.proxy_host.get().strip()
            proxy_port = self.proxy_port.get().strip()
            if proxy_host and proxy_port:
                self.tester.proxies = {
                    'http': f"http://{proxy_host}:{proxy_port}",
                    'https': f"http://{proxy_host}:{proxy_port}"
                }
        else:
            self.tester.proxies = None
        
        # Configure other options
        self.tester.verify_ssl = self.verify_ssl.get()
        try:
            self.tester.timeout = int(self.timeout_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Timeout must be a number")
            return
        
        try:
            # Clear previous results
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            
            # Run test
            self.current_results = self.tester.test_cors(
                url, selected_methods, headers, collaborator, custom_origin
            )
            
            # Display results
            for method, data in self.current_results.items():
                if 'error' in data:
                    self.results_tree.insert('', tk.END, values=(
                        method, 'ERROR', '', '', data['error'], ''
                    ), tags=('error',))
                    continue
                
                cors = data['cors_headers']
                self.results_tree.insert('', tk.END, values=(
                    method,
                    data['status_code'],
                    cors['ACAO'],
                    cors['ACAC'],
                    data['vulnerability'],
                    f"{data['response_time']:.2f}"
                ), tags=(self.get_severity_tag(data['vulnerability']),))
            
            messagebox.showinfo("Test Complete", f"CORS test completed for {url}")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def get_severity_tag(self, vulnerability):
        if "CRITICAL" in vulnerability:
            return 'critical'
        elif "VULNERABLE" in vulnerability:
            return 'vulnerable'
        elif "Warning" in vulnerability:
            return 'warning'
        return 'secure'
    
    def show_details(self, event):
        selected_item = self.results_tree.selection()
        if not selected_item:
            return
        
        item = self.results_tree.item(selected_item[0])
        method = item['values'][0]
        
        if not self.current_results or method not in self.current_results:
            return
        
        data = self.current_results[method]
        self.details_text.delete(1.0, tk.END)
        
        if 'error' in data:
            self.details_text.insert(tk.END, f"Error for {method} request:\n")
            self.details_text.insert(tk.END, f"{data['error']}\n")
            return
        
        self.details_text.insert(tk.END, f"=== {method} Request Details ===\n\n")
        self.details_text.insert(tk.END, f"URL: {data['url']}\n")
        self.details_text.insert(tk.END, f"Origin Used: {data['origin_used']}\n")
        self.details_text.insert(tk.END, f"Status Code: {data['status_code']}\n")
        self.details_text.insert(tk.END, f"Response Time: {data['response_time']:.2f}s\n")
        self.details_text.insert(tk.END, f"Timestamp: {data['timestamp']}\n\n")
        
        self.details_text.insert(tk.END, "=== Request Headers ===\n")
        for k, v in data['request_headers'].items():
            self.details_text.insert(tk.END, f"{k}: {v}\n")
        
        self.details_text.insert(tk.END, "\n=== Response Headers ===\n")
        for k, v in data['response_headers'].items():
            self.details_text.insert(tk.END, f"{k}: {v}\n")
        
        self.details_text.insert(tk.END, "\n=== CORS Headers ===\n")
        for k, v in data['cors_headers'].items():
            if v:  # Only show non-empty headers
                self.details_text.insert(tk.END, f"{k}: {v}\n")
        
        self.details_text.insert(tk.END, "\n=== Vulnerability Notes ===\n")
        for note in data['notes']:
            self.details_text.insert(tk.END, f"- {note}\n")
    
    def clear_results(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.details_text.delete(1.0, tk.END)
        self.current_results = None
    
    def export_results(self):
        if not self.current_results:
            messagebox.showerror("Error", "No results to export")
            return
        
        file_types = [
            ('JSON', '*.json'),
            ('CSV', '*.csv'),
            ('Text', '*.txt'),
            ('All Files', '*.*')
        ]
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=file_types,
            title="Save Test Results"
        )
        
        if not file_path:
            return
        
        try:
            ext = os.path.splitext(file_path)[1].lower()
            
            if ext == '.json':
                with open(file_path, 'w') as f:
                    json.dump(self.current_results, f, indent=2)
            elif ext == '.csv':
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Method', 'Status', 'ACA-Origin', 'ACA-Credentials', 'Vulnerability', 'Time', 'Notes'])
                    
                    for method, data in self.current_results.items():
                        if 'error' in data:
                            writer.writerow([method, 'ERROR', '', '', data['error'], '', ''])
                        else:
                            notes = '\n'.join(data['notes'])
                            writer.writerow([
                                method,
                                data['status_code'],
                                data['cors_headers']['ACAO'],
                                data['cors_headers']['ACAC'],
                                data['vulnerability'],
                                f"{data['response_time']:.2f}",
                                notes
                            ])
            else:  # txt or other
                with open(file_path, 'w') as f:
                    f.write(f"CORS Test Results\n{'='*50}\n\n")
                    for method, data in self.current_results.items():
                        f.write(f"Method: {method}\n")
                        if 'error' in data:
                            f.write(f"Error: {data['error']}\n\n")
                            continue
                        
                        f.write(f"Status: {data['status_code']}\n")
                        f.write(f"Response Time: {data['response_time']:.2f}s\n")
                        f.write(f"Vulnerability: {data['vulnerability']}\n")
                        f.write("\nCORS Headers:\n")
                        for k, v in data['cors_headers'].items():
                            if v:
                                f.write(f"  {k}: {v}\n")
                        
                        f.write("\nNotes:\n")
                        for note in data['notes']:
                            f.write(f"- {note}\n")
                        
                        f.write("\n" + "="*50 + "\n\n")
            
            messagebox.showinfo("Success", f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="CORS Vulnerability Tester")
    parser.add_argument("--gui", action="store_true", help="Launch GUI version")
    args = parser.parse_args()
    
    if args.gui:
        root = tk.Tk()
        app = CORSGUI(root)
        root.mainloop()
    else:
        # Command-line version
        tester = CORSTester()
        
        print("CORS Vulnerability Tester - Command Line Mode")
        print("Developed by AppSecWarrior | https://github.com/appsecwarrior")
        print("For More Security Articale follow us | https://medium.com/@appsecwarrior")
        print("="*50)
        
        url = input("\nEnter target URL: ").strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        print("\nAvailable methods:", ", ".join(tester.methods))
        methods = input("Enter methods to test (comma separated, or 'all'): ").strip()
        if methods.lower() == 'all':
            methods = tester.methods
        else:
            methods = [m.strip().upper() for m in methods.split(',')]
        
        print("\nDefault headers:", tester.default_headers)
        custom_headers = input("Enter additional headers (header:value, comma separated): ").strip()
        headers = tester.default_headers.copy()
        if custom_headers:
            for h in custom_headers.split(','):
                if ':' in h:
                    header, value = h.split(':', 1)
                    headers[header.strip()] = value.strip()
        
        custom_origin = input("Custom origin to test (leave empty for default): ").strip() or None
        collaborator = input("Burp Collaborator host (leave empty to skip): ").strip() or None
        
        use_proxy = input("Use Burp Proxy? (y/n): ").strip().lower() == 'y'
        if use_proxy:
            proxy_host = input("Proxy host [127.0.0.1]: ").strip() or "127.0.0.1"
            proxy_port = input("Proxy port [8080]: ").strip() or "8080"
            tester.proxies = {
                'http': f"http://{proxy_host}:{proxy_port}",
                'https': f"http://{proxy_host}:{proxy_port}"
            }
        
        verify_ssl = input("Verify SSL? (y/n): ").strip().lower() == 'y'
        tester.verify_ssl = verify_ssl
        
        try:
            timeout = int(input("Timeout in seconds [15]: ").strip() or "15")
            tester.timeout = timeout
        except ValueError:
            print("Invalid timeout, using default 15 seconds")
            tester.timeout = 15
        
        print("\nTesting CORS configuration...")
        results = tester.test_cors(url, methods, headers, collaborator, custom_origin)
        
        print("\nResults:")
        print("{:<8} {:<8} {:<20} {:<10} {:<30} {:<10}".format(
            'Method', 'Status', 'ACA-Origin', 'ACA-Cred', 'Vulnerability', 'Time(s)'))
        print("-" * 90)
        
        for method, data in results.items():
            if 'error' in data:
                print("{:<8} {:<8} {:<20} {:<10} {:<30} {:<10}".format(
                    method, 'ERROR', '', '', data['error'], ''))
                continue
            
            cors = data['cors_headers']
            print("{:<8} {:<8} {:<20} {:<10} {:<30} {:<10.2f}".format(
                method,
                data['status_code'],
                cors['ACAO'],
                cors['ACAC'],
                data['vulnerability'],
                data['response_time']
            ))
            
            if data['notes']:
                print("    Notes:")
                for note in data['notes']:
                    print(f"    - {note}")
                print()

if __name__ == "__main__":
    main()