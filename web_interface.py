#!/usr/bin/env python3
"""
Interfaz Web para KaliScanner
Proporciona una interfaz moderna y fácil de usar
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import json
import os
import threading
import time
from datetime import datetime
import subprocess
import sys

# Importar nuestro escáner
from kali_scanner import PortScanner, ReportGenerator

app = Flask(__name__)
CORS(app)

# Estado global del escáner
scan_status = {
    'running': False,
    'progress': 0,
    'current_host': '',
    'results': {},
    'start_time': None,
    'scan_id': None
}

@app.route('/')
def index():
    """Página principal"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Iniciar un nuevo escaneo"""
    global scan_status
    
    if scan_status['running']:
        return jsonify({'error': 'Ya hay un escaneo en progreso'}), 400
    
    data = request.json
    target = data.get('target')
    ports = data.get('ports', 'common')
    threads = data.get('threads', 100)
    
    if not target:
        return jsonify({'error': 'Target es requerido'}), 400
    
    # Iniciar escaneo en hilo separado
    scan_thread = threading.Thread(
        target=run_scan_thread,
        args=(target, ports, threads)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({'message': 'Escaneo iniciado', 'scan_id': scan_status['scan_id']})

@app.route('/api/status')
def get_status():
    """Obtener estado del escaneo"""
    return jsonify(scan_status)

@app.route('/api/results')
def get_results():
    """Obtener resultados del escaneo"""
    return jsonify(scan_status['results'])

@app.route('/api/download/<format>')
def download_report(format):
    """Descargar reporte en formato específico"""
    if not scan_status['results']:
        return jsonify({'error': 'No hay resultados disponibles'}), 404
    
    report_gen = ReportGenerator()
    
    if format == 'json':
        filename = report_gen.generate_json_report(scan_status['results'])
        return send_file(filename, as_attachment=True)
    elif format == 'html':
        filename = report_gen.generate_html_report(scan_status['results'])
        return send_file(filename, as_attachment=True)
    else:
        return jsonify({'error': 'Formato no soportado'}), 400

def run_scan_thread(target, ports, threads):
    """Ejecutar escaneo en hilo separado"""
    global scan_status
    
    scan_status['running'] = True
    scan_status['progress'] = 0
    scan_status['current_host'] = target
    scan_status['start_time'] = time.time()
    scan_status['scan_id'] = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        scanner = PortScanner(threads=threads)
        
        # Configurar puertos
        if ports == 'common':
            port_list = None
        elif ports == 'all':
            port_list = list(range(1, 65536))
        elif '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, end + 1))
        elif ',' in ports:
            port_list = [int(p.strip()) for p in ports.split(',')]
        else:
            port_list = [int(ports)]
        
        # Realizar escaneo
        if '/' in target:
            results = scanner.scan_network(target, port_list)
        else:
            results = {target: scanner.scan_host(target, port_list)}
        
        scan_status['results'] = results
        scan_status['progress'] = 100
        
    except Exception as e:
        scan_status['error'] = str(e)
    finally:
        scan_status['running'] = False

# Template HTML integrado
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliScanner - Interfaz Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .main-content {
            padding: 30px;
        }
        
        .scan-form {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr;
            gap: 20px;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .status-panel {
            background: #e8f4fd;
            border: 2px solid #3498db;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            display: none;
        }
        
        .status-panel.active {
            display: block;
        }
        
        .progress-bar {
            background: #e0e0e0;
            border-radius: 10px;
            height: 20px;
            margin: 10px 0;
            overflow: hidden;
        }
        
        .progress-fill {
            background: linear-gradient(90deg, #27ae60, #2ecc71);
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }
        
        .results-panel {
            display: none;
        }
        
        .results-panel.active {
            display: block;
        }
        
        .host-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .host-header {
            background: #34495e;
            color: white;
            padding: 15px;
            font-weight: bold;
        }
        
        .ports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            padding: 20px;
        }
        
        .port-card {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
        }
        
        .port-number {
            font-size: 1.2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .port-service {
            color: #7f8c8d;
            margin: 5px 0;
        }
        
        .vulnerabilities {
            margin-top: 10px;
        }
        
        .vuln-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 2px;
        }
        
        .vuln-critical {
            background: #e74c3c;
            color: white;
        }
        
        .vuln-high {
            background: #f39c12;
            color: white;
        }
        
        .vuln-medium {
            background: #f1c40f;
            color: #2c3e50;
        }
        
        .vuln-low {
            background: #27ae60;
            color: white;
        }
        
        .download-buttons {
            text-align: center;
            margin: 20px 0;
        }
        
        .download-buttons .btn {
            margin: 0 10px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .stat-card p {
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ KaliScanner</h1>
            <p>Escáner de Vulnerabilidades y Puertos - Interfaz Web</p>
        </div>
        
        <div class="main-content">
            <div class="scan-form">
                <h2>Configurar Escaneo</h2>
                <form id="scanForm">
                    <div class="form-group">
                        <label for="target">Target (IP, hostname o red):</label>
                        <input type="text" id="target" name="target" placeholder="192.168.1.1 o example.com" required>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="ports">Puertos:</label>
                            <select id="ports" name="ports">
                                <option value="common">Puertos Comunes</option>
                                <option value="all">Todos los Puertos (1-65535)</option>
                                <option value="1-1000">Rango 1-1000</option>
                                <option value="custom">Personalizado</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="threads">Hilos:</label>
                            <input type="number" id="threads" name="threads" value="100" min="1" max="500">
                        </div>
                        
                        <div class="form-group">
                            <label>&nbsp;</label>
                            <button type="submit" class="btn" id="startBtn">🚀 Iniciar Escaneo</button>
                        </div>
                    </div>
                    
                    <div class="form-group" id="customPorts" style="display: none;">
                        <label for="customPortsInput">Puertos personalizados:</label>
                        <input type="text" id="customPortsInput" placeholder="80,443,22 o 1-1000">
                    </div>
                </form>
            </div>
            
            <div class="status-panel" id="statusPanel">
                <h3>Estado del Escaneo</h3>
                <div id="statusInfo">
                    <p>Preparando escaneo...</p>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill"></div>
                </div>
                <div id="progressText">0%</div>
            </div>
            
            <div class="results-panel" id="resultsPanel">
                <h2>Resultados del Escaneo</h2>
                
                <div class="download-buttons">
                    <button class="btn" onclick="downloadReport('json')">📄 Descargar JSON</button>
                    <button class="btn" onclick="downloadReport('html')">🌐 Descargar HTML</button>
                </div>
                
                <div class="stats" id="statsContainer">
                    <!-- Stats will be populated by JavaScript -->
                </div>
                
                <div id="resultsContainer">
                    <!-- Results will be populated by JavaScript -->
                </div>
            </div>
        </div>
    </div>

    <script>
        let scanInterval;
        
        document.getElementById('ports').addEventListener('change', function() {
            const customPorts = document.getElementById('customPorts');
            if (this.value === 'custom') {
                customPorts.style.display = 'block';
            } else {
                customPorts.style.display = 'none';
            }
        });
        
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
        
        function startScan() {
            const formData = new FormData(document.getElementById('scanForm'));
            const target = formData.get('target');
            let ports = formData.get('ports');
            const threads = parseInt(formData.get('threads'));
            
            if (ports === 'custom') {
                ports = document.getElementById('customPortsInput').value;
            }
            
            const data = {
                target: target,
                ports: ports,
                threads: threads
            };
            
            fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    document.getElementById('startBtn').disabled = true;
                    document.getElementById('statusPanel').classList.add('active');
                    document.getElementById('resultsPanel').classList.remove('active');
                    
                    // Start polling for status
                    scanInterval = setInterval(checkStatus, 1000);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error al iniciar el escaneo');
            });
        }
        
        function checkStatus() {
            fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                updateStatus(data);
                
                if (!data.running && data.progress > 0) {
                    clearInterval(scanInterval);
                    loadResults();
                }
            })
            .catch(error => {
                console.error('Error checking status:', error);
            });
        }
        
        function updateStatus(status) {
            const statusInfo = document.getElementById('statusInfo');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            
            if (status.running) {
                statusInfo.innerHTML = `<p>Escaneando: ${status.current_host}</p>`;
                progressFill.style.width = status.progress + '%';
                progressText.textContent = status.progress + '%';
            } else if (status.progress > 0) {
                statusInfo.innerHTML = '<p>✅ Escaneo completado</p>';
                progressFill.style.width = '100%';
                progressText.textContent = '100%';
                document.getElementById('startBtn').disabled = false;
            }
        }
        
        function loadResults() {
            fetch('/api/results')
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                document.getElementById('resultsPanel').classList.add('active');
            })
            .catch(error => {
                console.error('Error loading results:', error);
            });
        }
        
        function displayResults(results) {
            const container = document.getElementById('resultsContainer');
            const statsContainer = document.getElementById('statsContainer');
            
            // Calculate stats
            let totalHosts = Object.keys(results).length;
            let totalPorts = 0;
            let totalVulns = 0;
            
            for (const host in results) {
                totalPorts += results[host].length;
                for (const result of results[host]) {
                    totalVulns += result.vulnerabilities.length;
                }
            }
            
            // Display stats
            statsContainer.innerHTML = `
                <div class="stat-card">
                    <h3>${totalHosts}</h3>
                    <p>Hosts</p>
                </div>
                <div class="stat-card">
                    <h3>${totalPorts}</h3>
                    <p>Puertos Abiertos</p>
                </div>
                <div class="stat-card">
                    <h3>${totalVulns}</h3>
                    <p>Vulnerabilidades</p>
                </div>
            `;
            
            // Display results
            let html = '';
            for (const host in results) {
                html += `
                    <div class="host-card">
                        <div class="host-header">📡 ${host} (${results[host].length} puertos abiertos)</div>
                        <div class="ports-grid">
                `;
                
                for (const result of results[host]) {
                    html += `
                        <div class="port-card">
                            <div class="port-number">Puerto ${result.port}</div>
                            <div class="port-service">${result.service} - ${result.version}</div>
                    `;
                    
                    if (result.vulnerabilities.length > 0) {
                        html += '<div class="vulnerabilities">';
                        for (const vuln of result.vulnerabilities) {
                            html += `<span class="vuln-badge vuln-${vuln.severity.toLowerCase()}">${vuln.cve_id}</span>`;
                        }
                        html += '</div>';
                    }
                    
                    html += '</div>';
                }
                
                html += '</div></div>';
            }
            
            container.innerHTML = html;
        }
        
        function downloadReport(format) {
            window.open(`/api/download/${format}`, '_blank');
        }
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("🌐 Iniciando interfaz web de KaliScanner...")
    print("📍 Accede a: http://localhost:5000")
    print("🛑 Presiona Ctrl+C para detener")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
