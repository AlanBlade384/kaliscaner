#!/usr/bin/env python3
"""
KaliScanner - Escáner de Vulnerabilidades y Puertos
Similar a Nessus pero open source para Kali Linux
"""

import socket
import threading
import subprocess
import json
import time
import argparse
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Dict, Optional
import sqlite3
import hashlib

@dataclass
class ScanResult:
    """Resultado de escaneo de un puerto"""
    host: str
    port: int
    state: str
    service: str = ""
    version: str = ""
    vulnerabilities: List[Dict] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []

@dataclass
class VulnerabilityInfo:
    """Información de vulnerabilidad"""
    cve_id: str
    severity: str
    description: str
    solution: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

class VulnerabilityDatabase:
    """Base de datos de vulnerabilidades"""
    
    def __init__(self, db_path="vulnerabilities.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializar base de datos SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                service TEXT,
                version_pattern TEXT,
                severity TEXT,
                description TEXT,
                solution TEXT,
                references TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insertar algunas vulnerabilidades comunes
        common_vulns = [
            ("CVE-2017-0144", "smb", ".*", "CRITICAL", 
             "EternalBlue - Vulnerabilidad en SMBv1 que permite ejecución remota de código",
             "Deshabilitar SMBv1 o aplicar parches de seguridad",
             "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"),
            
            ("CVE-2014-6271", "bash", ".*", "HIGH",
             "Shellshock - Vulnerabilidad en Bash que permite ejecución de comandos",
             "Actualizar Bash a una versión parcheada",
             "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"),
            
            ("CVE-2021-44228", "java", ".*log4j.*", "CRITICAL",
             "Log4Shell - Vulnerabilidad RCE en Apache Log4j",
             "Actualizar Log4j a versión 2.17.0 o superior",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
            
            ("CVE-2019-0708", "rdp", ".*", "CRITICAL",
             "BlueKeep - Vulnerabilidad RCE en RDP de Windows",
             "Aplicar parches de seguridad de Microsoft",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"),
            
            ("CVE-2017-7494", "smb", "samba.*", "HIGH",
             "SambaCry - Vulnerabilidad RCE en Samba",
             "Actualizar Samba a versión 4.6.4 o superior",
             "https://nvd.nist.gov/vuln/detail/CVE-2017-7494")
        ]
        
        for vuln in common_vulns:
            cursor.execute('''
                INSERT OR IGNORE INTO vulnerabilities 
                (cve_id, service, version_pattern, severity, description, solution, references)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', vuln)
        
        conn.commit()
        conn.close()
    
    def search_vulnerabilities(self, service: str, version: str = "") -> List[VulnerabilityInfo]:
        """Buscar vulnerabilidades para un servicio específico"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT cve_id, severity, description, solution, references
            FROM vulnerabilities
            WHERE service = ? OR service = '*'
        ''', (service.lower(),))
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vuln = VulnerabilityInfo(
                cve_id=row[0],
                severity=row[1],
                description=row[2],
                solution=row[3],
                references=row[4].split(',') if row[4] else []
            )
            vulnerabilities.append(vuln)
        
        conn.close()
        return vulnerabilities

class PortScanner:
    """Escáner de puertos principal"""
    
    def __init__(self, threads=100, timeout=3):
        self.threads = threads
        self.timeout = timeout
        self.vuln_db = VulnerabilityDatabase()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6000, 6001, 8080, 8443, 8888, 9100
        ]
        
    def scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        """Escanear un puerto específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service, version = self.detect_service(host, port)
                scan_result = ScanResult(
                    host=host,
                    port=port,
                    state="open",
                    service=service,
                    version=version
                )
                
                # Buscar vulnerabilidades
                vulnerabilities = self.vuln_db.search_vulnerabilities(service, version)
                scan_result.vulnerabilities = [
                    {
                        "cve_id": vuln.cve_id,
                        "severity": vuln.severity,
                        "description": vuln.description,
                        "solution": vuln.solution
                    }
                    for vuln in vulnerabilities
                ]
                
                return scan_result
        except Exception as e:
            pass
        
        return None
    
    def detect_service(self, host: str, port: int) -> tuple:
        """Detectar servicio y versión en un puerto"""
        service_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc"
        }
        
        service = service_map.get(port, "unknown")
        version = ""
        
        try:
            # Intentar banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            if port in [21, 22, 25, 110]:
                # Servicios que envían banner automáticamente
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                version = banner[:100]  # Limitar longitud
            elif port in [80, 443]:
                # HTTP/HTTPS
                request = b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
                sock.send(request)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "Server:" in response:
                    for line in response.split('\n'):
                        if line.startswith('Server:'):
                            version = line.split(':', 1)[1].strip()[:50]
                            break
            
            sock.close()
        except:
            pass
        
        return service, version
    
    def scan_host(self, host: str, ports: List[int] = None) -> List[ScanResult]:
        """Escanear todos los puertos de un host"""
        if ports is None:
            ports = self.common_ports
        
        print(f"[+] Escaneando {host} en {len(ports)} puertos...")
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    print(f"[+] Puerto abierto: {result.port} ({result.service}) - {result.version}")
                    if result.vulnerabilities:
                        print(f"    [!] {len(result.vulnerabilities)} vulnerabilidades encontradas")
        
        return results
    
    def scan_network(self, network: str, ports: List[int] = None) -> Dict[str, List[ScanResult]]:
        """Escanear una red completa"""
        # Implementación básica para rango de IPs
        results = {}
        
        if '/' in network:
            # CIDR notation
            print(f"[+] Escaneando red {network}")
            # Aquí se implementaría el escaneo de red CIDR
            # Por simplicidad, solo escaneamos el host base
            base_ip = network.split('/')[0]
            results[base_ip] = self.scan_host(base_ip, ports)
        else:
            # IP única
            results[network] = self.scan_host(network, ports)
        
        return results

class ReportGenerator:
    """Generador de reportes"""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_json_report(self, scan_results: Dict[str, List[ScanResult]], filename: str = None):
        """Generar reporte en formato JSON"""
        if filename is None:
            filename = f"scan_report_{self.timestamp}.json"
        
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "scanner": "KaliScanner v1.0",
                "total_hosts": len(scan_results)
            },
            "results": {}
        }
        
        for host, results in scan_results.items():
            report_data["results"][host] = {
                "total_open_ports": len(results),
                "ports": [
                    {
                        "port": result.port,
                        "state": result.state,
                        "service": result.service,
                        "version": result.version,
                        "vulnerabilities": result.vulnerabilities
                    }
                    for result in results
                ]
            }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Reporte JSON guardado: {filename}")
        return filename
    
    def generate_html_report(self, scan_results: Dict[str, List[ScanResult]], filename: str = None):
        """Generar reporte en formato HTML"""
        if filename is None:
            filename = f"scan_report_{self.timestamp}.html"
        
        html_content = self._create_html_template(scan_results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] Reporte HTML guardado: {filename}")
        return filename
    
    def _create_html_template(self, scan_results: Dict[str, List[ScanResult]]) -> str:
        """Crear template HTML para el reporte"""
        total_hosts = len(scan_results)
        total_open_ports = sum(len(results) for results in scan_results.values())
        total_vulnerabilities = sum(
            len(result.vulnerabilities) 
            for results in scan_results.values() 
            for result in results
        )
        
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliScanner - Reporte de Escaneo</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header p {{ color: #7f8c8d; margin: 10px 0 0 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-card h3 {{ margin: 0; font-size: 2em; }}
        .stat-card p {{ margin: 5px 0 0 0; opacity: 0.9; }}
        .host-section {{ margin-bottom: 30px; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; }}
        .host-header {{ background: #34495e; color: white; padding: 15px; font-weight: bold; font-size: 1.2em; }}
        .port-table {{ width: 100%; border-collapse: collapse; }}
        .port-table th {{ background: #ecf0f1; padding: 12px; text-align: left; border-bottom: 1px solid #bdc3c7; }}
        .port-table td {{ padding: 12px; border-bottom: 1px solid #ecf0f1; }}
        .port-table tr:hover {{ background: #f8f9fa; }}
        .vulnerability {{ background: #fff5f5; border-left: 4px solid #e74c3c; padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .severity-critical {{ border-left-color: #c0392b; background: #fdf2f2; }}
        .severity-high {{ border-left-color: #e74c3c; background: #fef5f5; }}
        .severity-medium {{ border-left-color: #f39c12; background: #fef9f3; }}
        .severity-low {{ border-left-color: #27ae60; background: #f4f9f4; }}
        .vuln-title {{ font-weight: bold; color: #2c3e50; }}
        .vuln-description {{ margin: 5px 0; color: #5d6d7e; }}
        .timestamp {{ text-align: center; margin-top: 30px; color: #7f8c8d; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ KaliScanner</h1>
            <p>Reporte de Escaneo de Vulnerabilidades y Puertos</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{total_hosts}</h3>
                <p>Hosts Escaneados</p>
            </div>
            <div class="stat-card">
                <h3>{total_open_ports}</h3>
                <p>Puertos Abiertos</p>
            </div>
            <div class="stat-card">
                <h3>{total_vulnerabilities}</h3>
                <p>Vulnerabilidades</p>
            </div>
        </div>
"""
        
        for host, results in scan_results.items():
            html += f"""
        <div class="host-section">
            <div class="host-header">📡 Host: {host} ({len(results)} puertos abiertos)</div>
            <table class="port-table">
                <thead>
                    <tr>
                        <th>Puerto</th>
                        <th>Servicio</th>
                        <th>Versión</th>
                        <th>Vulnerabilidades</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for result in results:
                vuln_count = len(result.vulnerabilities)
                vuln_text = f"{vuln_count} vulnerabilidades" if vuln_count > 0 else "Ninguna"
                
                html += f"""
                    <tr>
                        <td><strong>{result.port}</strong></td>
                        <td>{result.service}</td>
                        <td>{result.version}</td>
                        <td>{vuln_text}</td>
                    </tr>
"""
                
                if result.vulnerabilities:
                    html += f"""
                    <tr>
                        <td colspan="4">
"""
                    for vuln in result.vulnerabilities:
                        severity_class = f"severity-{vuln['severity'].lower()}"
                        html += f"""
                            <div class="vulnerability {severity_class}">
                                <div class="vuln-title">{vuln['cve_id']} - {vuln['severity']}</div>
                                <div class="vuln-description">{vuln['description']}</div>
                                <div><strong>Solución:</strong> {vuln['solution']}</div>
                            </div>
"""
                    html += """
                        </td>
                    </tr>
"""
            
            html += """
                </tbody>
            </table>
        </div>
"""
        
        html += f"""
        <div class="timestamp">
            Reporte generado el {datetime.now().strftime("%d/%m/%Y a las %H:%M:%S")}
        </div>
    </div>
</body>
</html>
"""
        
        return html

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="KaliScanner - Escáner de Vulnerabilidades y Puertos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 kali_scanner.py -t 192.168.1.1
  python3 kali_scanner.py -t 192.168.1.0/24 -p 1-1000
  python3 kali_scanner.py -t example.com -p 80,443,22 --threads 50
  python3 kali_scanner.py -t 10.0.0.1 --all-ports --output json
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='IP, hostname o rango de red a escanear')
    parser.add_argument('-p', '--ports', default='common',
                       help='Puertos a escanear (common, all, 1-1000, o lista: 80,443,22)')
    parser.add_argument('--threads', type=int, default=100,
                       help='Número de hilos (default: 100)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Timeout en segundos (default: 3)')
    parser.add_argument('--output', choices=['json', 'html', 'both'], default='both',
                       help='Formato de salida del reporte')
    parser.add_argument('--all-ports', action='store_true',
                       help='Escanear todos los puertos (1-65535)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Modo verbose')
    
    args = parser.parse_args()
    
    # Banner
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                        🛡️  KaliScanner v1.0                   ║
║              Escáner de Vulnerabilidades y Puertos           ║
║                     Similar a Nessus                         ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Configurar puertos
    if args.all_ports:
        ports = list(range(1, 65536))
    elif args.ports == 'common':
        ports = None  # Usar puertos comunes por defecto
    elif '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        try:
            ports = [int(args.ports)]
        except ValueError:
            print("❌ Error: Formato de puertos inválido")
            sys.exit(1)
    
    # Inicializar escáner
    scanner = PortScanner(threads=args.threads, timeout=args.timeout)
    
    print(f"🎯 Target: {args.target}")
    print(f"🔧 Hilos: {args.threads}")
    print(f"⏱️  Timeout: {args.timeout}s")
    print(f"🔍 Puertos: {len(ports) if ports else 'Comunes'}")
    print("=" * 60)
    
    start_time = time.time()
    
    try:
        # Realizar escaneo
        if '/' in args.target:
            results = scanner.scan_network(args.target, ports)
        else:
            results = {args.target: scanner.scan_host(args.target, ports)}
        
        # Generar reportes
        report_gen = ReportGenerator()
        
        if args.output in ['json', 'both']:
            report_gen.generate_json_report(results)
        
        if args.output in ['html', 'both']:
            report_gen.generate_html_report(results)
        
        # Estadísticas finales
        total_hosts = len(results)
        total_open_ports = sum(len(host_results) for host_results in results.values())
        total_vulnerabilities = sum(
            len(result.vulnerabilities) 
            for host_results in results.values() 
            for result in host_results
        )
        
        elapsed_time = time.time() - start_time
        
        print("\n" + "=" * 60)
        print("📊 RESUMEN DEL ESCANEO")
        print("=" * 60)
        print(f"🏠 Hosts escaneados: {total_hosts}")
        print(f"🔓 Puertos abiertos: {total_open_ports}")
        print(f"⚠️  Vulnerabilidades: {total_vulnerabilities}")
        print(f"⏱️  Tiempo total: {elapsed_time:.2f} segundos")
        print("=" * 60)
        
        if total_vulnerabilities > 0:
            print("⚠️  ¡ATENCIÓN! Se encontraron vulnerabilidades. Revisa los reportes generados.")
        else:
            print("✅ No se encontraron vulnerabilidades conocidas.")
            
    except KeyboardInterrupt:
        print("\n❌ Escaneo interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error durante el escaneo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
