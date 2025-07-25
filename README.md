# Advanced Scanner para KaliScanner

## Descripción

**Advanced Scanner** es una herramienta de análisis de seguridad automatizada para pentesting. Permite detectar vulnerabilidades web, información de red y exploits conocidos en un objetivo (dominio, IP o sitio web).

## Características

- **Vulnerabilidades Web:** SQL Injection, XSS, archivos sensibles, headers de seguridad, fallos SSL/TLS.
- **Red:** Enumeración DNS, subdominios, banner grabbing de puertos.
- **Exploits:** Detección de EternalBlue (MS17-010) y Shellshock.

## Instalación

1. Clona el repositorio o descarga los archivos.
2. Instala los requisitos:
   ```bash
   pip install -r requirements.txt
   ./install.sh
Modo de uso
bash

    python advanced_scanner.py -t <objetivo> -s <tipo>
-t o --target: Especifica el objetivo a analizar (puede ser dominio, IP o URL).
-s o --scan-type: Selecciona el tipo de escaneo:
all (predeterminado): Realiza todos los escaneos (web, red, exploits).
web
: Solo busca vulnerabilidades web.
dns
: Solo realiza análisis DNS y subdominios.
exploit: Solo busca exploits conocidos.
Ejemplo de uso
bash
   
    python advanced_scanner.py -t ejemplo.com -s all
Esto analizará ejemplo.com buscando vulnerabilidades web, información DNS/subdominios y exploits.
