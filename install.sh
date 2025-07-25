#!/bin/bash

# KaliScanner - Script de Instalación para Kali Linux
# Instala todas las dependencias necesarias

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    🛡️  KaliScanner Installer                  ║"
echo "║              Instalación para Kali Linux                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Verificar si se ejecuta como root
if [[ $EUID -eq 0 ]]; then
   echo "❌ No ejecutes este script como root"
   exit 1
fi

# Verificar si estamos en Kali Linux
if ! grep -q "kali" /etc/os-release; then
    echo "⚠️  Advertencia: Este script está optimizado para Kali Linux"
    read -p "¿Continuar de todos modos? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "🔄 Actualizando repositorios..."
sudo apt update

echo "📦 Instalando dependencias del sistema..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    masscan \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    whatweb \
    wapiti \
    nuclei \
    git \
    curl \
    wget

echo "🐍 Creando entorno virtual de Python..."
python3 -m venv venv
source venv/bin/activate

echo "📚 Instalando dependencias de Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🔧 Configurando permisos..."
chmod +x kali_scanner.py
chmod +x web_interface.py

echo "📁 Creando directorios necesarios..."
mkdir -p reports
mkdir -p logs
mkdir -p wordlists

echo "📝 Descargando wordlists comunes..."
cd wordlists

# SecLists
if [ ! -d "SecLists" ]; then
    echo "Descargando SecLists..."
    git clone https://github.com/danielmiessler/SecLists.git
fi

# Common wordlists
if [ ! -f "common.txt" ]; then
    echo "Descargando wordlist común..."
    wget -O common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
fi

cd ..

echo "🛠️  Configurando alias útiles..."
cat >> ~/.bashrc << 'EOF'

# KaliScanner Aliases
alias kaliscanner='cd /path/to/kaliscanner && source venv/bin/activate && python3 kali_scanner.py'
alias kaliscanner-web='cd /path/to/kaliscanner && source venv/bin/activate && python3 web_interface.py'
alias kaliscanner-update='cd /path/to/kaliscanner && git pull && source venv/bin/activate && pip install -r requirements.txt'
EOF

# Reemplazar ruta actual
sed -i "s|/path/to/kaliscanner|$(pwd)|g" ~/.bashrc

echo "🔍 Creando script de escaneo rápido..."
cat > quick_scan.sh << 'EOF'
#!/bin/bash
# Script de escaneo rápido

if [ $# -eq 0 ]; then
    echo "Uso: $0 <target> [puertos]"
    echo "Ejemplos:"
    echo "  $0 192.168.1.1"
    echo "  $0 example.com 80,443,22"
    echo "  $0 10.0.0.0/24 1-1000"
    exit 1
fi

TARGET=$1
PORTS=${2:-"common"}

echo "🎯 Iniciando escaneo rápido de $TARGET"
echo "🔍 Puertos: $PORTS"

source venv/bin/activate
python3 kali_scanner.py -t "$TARGET" -p "$PORTS" --output both

echo "✅ Escaneo completado. Revisa los reportes generados."
EOF

chmod +x quick_scan.sh

echo "🌐 Creando script de inicio web..."
cat > start_web.sh << 'EOF'
#!/bin/bash
# Iniciar interfaz web

echo "🌐 Iniciando KaliScanner Web Interface..."
echo "📍 La interfaz estará disponible en: http://localhost:5000"
echo "🛑 Presiona Ctrl+C para detener"

source venv/bin/activate
python3 web_interface.py
EOF

chmod +x start_web.sh

echo "📋 Creando script de actualización..."
cat > update.sh << 'EOF'
#!/bin/bash
# Script de actualización

echo "🔄 Actualizando KaliScanner..."

# Actualizar base de vulnerabilidades
echo "📊 Actualizando base de datos de vulnerabilidades..."
source venv/bin/activate
python3 -c "
from kali_scanner import VulnerabilityDatabase
db = VulnerabilityDatabase()
print('Base de datos actualizada')
"

# Actualizar wordlists
echo "📝 Actualizando wordlists..."
cd wordlists
if [ -d "SecLists" ]; then
    cd SecLists
    git pull
    cd ..
fi

# Actualizar dependencias
echo "📚 Actualizando dependencias..."
cd ..
source venv/bin/activate
pip install --upgrade -r requirements.txt

echo "✅ Actualización completada"
EOF

chmod +x update.sh

echo "📖 Creando documentación..."
cat > README.md << 'EOF'
# 🛡️ KaliScanner

Escáner de vulnerabilidades y puertos similar a Nessus, diseñado específicamente para Kali Linux.

## 🚀 Características

- **Escaneo de puertos** rápido y eficiente
- **Detección de servicios** y versiones
- **Base de datos de vulnerabilidades** integrada
- **Reportes HTML y JSON** profesionales
- **Interfaz web moderna** y fácil de usar
- **Multihilo** para máximo rendimiento
- **Compatible con Kali Linux**

## 📋 Uso

### Línea de comandos

```bash
# Escaneo básico
./quick_scan.sh 192.168.1.1

# Escaneo con puertos específicos
./quick_scan.sh example.com 80,443,22,21

# Escaneo de red completa
./quick_scan.sh 10.0.0.0/24 1-1000

# Escaneo avanzado
python3 kali_scanner.py -t 192.168.1.1 -p common --threads 200 --output both
```

### Interfaz Web

```bash
# Iniciar interfaz web
./start_web.sh

# Acceder a http://localhost:5000
```

## 🔧 Opciones

- `-t, --target`: IP, hostname o rango de red
- `-p, --ports`: Puertos a escanear (common, all, 1-1000, 80,443,22)
- `--threads`: Número de hilos (default: 100)
- `--timeout`: Timeout en segundos (default: 3)
- `--output`: Formato de salida (json, html, both)
- `--all-ports`: Escanear todos los puertos (1-65535)

## 📊 Reportes

Los reportes se generan automáticamente en formato HTML y JSON, incluyendo:

- Puertos abiertos por host
- Servicios y versiones detectadas
- Vulnerabilidades conocidas (CVE)
- Recomendaciones de seguridad
- Estadísticas del escaneo

## 🔄 Actualización

```bash
./update.sh
```

## 🛠️ Troubleshooting

### Error de permisos
```bash
chmod +x *.sh *.py
```

### Dependencias faltantes
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Puerto 5000 ocupado
Edita `web_interface.py` y cambia el puerto en la línea final.

## ⚠️ Advertencias Legales

- Solo usar en sistemas propios o con autorización explícita
- Respetar las leyes locales sobre pentesting
- No usar para actividades maliciosas
- El usuario es responsable del uso de esta herramienta

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

## 📄 Licencia

MIT License - Ver archivo LICENSE para detalles.
EOF

echo ""
echo "✅ ¡Instalación completada exitosamente!"
echo ""
echo "📋 Comandos disponibles:"
echo "  ./quick_scan.sh <target>     - Escaneo rápido"
echo "  ./start_web.sh               - Interfaz web"
echo "  ./update.sh                  - Actualizar herramienta"
echo ""
echo "🌐 Para usar la interfaz web:"
echo "  ./start_web.sh"
echo "  Luego abre: http://localhost:5000"
echo ""
echo "📚 Para usar desde línea de comandos:"
echo "  source venv/bin/activate"
echo "  python3 kali_scanner.py -t <target>"
echo ""
echo "📖 Lee README.md para más información"
echo ""
echo "🛡️  ¡Happy Hacking!"
