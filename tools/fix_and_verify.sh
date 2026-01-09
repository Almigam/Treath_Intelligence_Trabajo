#!/bin/bash
#
# Script de verificación y corrección de herramientas
#

BASE_DIR="$HOME/ThreatIntel-Exercise"
cd "$BASE_DIR" || exit 1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔═══════════════════════════════════════════╗"
echo "║   VERIFICACIÓN Y CORRECCIÓN               ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# Verificar scripts requeridos
REQUIRED_SCRIPTS=(
    "stix_generator.py"
    "yara_generator.py"
    "sigma_generator.py"
)

echo "[+] Verificando scripts..."
MISSING=0

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ -f "tools/$script" ]; then
        echo -e "  ${GREEN}✓${NC} $script"
    else
        echo -e "  ${RED}✗${NC} $script ${YELLOW}(FALTANTE)${NC}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""

if [ $MISSING -gt 0 ]; then
    echo -e "${YELLOW}[!] Faltan $MISSING scripts${NC}"
    echo ""
    echo "SOLUCIÓN:"
    echo "1. Copia los scripts generados por el asistente a tools/"
    echo "2. O descárgalos de tu conversación"
    echo ""
    echo "Estructura esperada:"
    echo "  tools/"
    echo "    ├── stix_generator.py"
    echo "    ├── yara_generator.py"
    echo "    └── sigma_generator.py"
    echo ""
    exit 1
fi

# Verificar permisos de ejecución
echo "[+] Verificando permisos..."
for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ -x "tools/$script" ]; then
        echo -e "  ${GREEN}✓${NC} $script (ejecutable)"
    else
        echo -e "  ${YELLOW}→${NC} Dando permisos a $script"
        chmod +x "tools/$script"
    fi
done

echo ""

# Verificar dependencias Python
echo "[+] Verificando dependencias Python..."

source venv/bin/activate

REQUIRED_PACKAGES=(
    "stix2"
    "pyyaml"
    "scapy"
    "requests"
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $package"
    else
        echo -e "  ${YELLOW}→${NC} Instalando $package..."
        pip install -q "$package"
    fi
done

echo ""

# Verificar archivos de entrada requeridos
echo "[+] Verificando archivos de entrada..."

REQUIRED_FILES=(
    "outputs/iocs/consolidated_iocs.json"
    "analysis/mitre/mitre_mapping.json"
    "analysis/correlation/attack_correlation.json"
)

ALL_OK=1
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file ${YELLOW}(FALTANTE)${NC}"
        ALL_OK=0
    fi
done

echo ""

if [ $ALL_OK -eq 0 ]; then
    echo -e "${RED}[!] Faltan archivos de análisis previo${NC}"
    echo ""
    echo "Ejecuta primero:"
    echo "  1. ./tools/run_analysis.sh"
    echo "  2. python3 tools/consolidate_iocs.py"
    echo "  3. python3 tools/correlate_attacks.py"
    echo "  4. python3 tools/mitre_mapper.py"
    echo ""
    exit 1
fi

# Todo OK - ejecutar estandarización
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   VERIFICACIÓN COMPLETADA                 ║${NC}"
echo -e "${GREEN}║   Todos los requisitos están listos      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}¿Ejecutar estandarización ahora? (y/n)${NC}"
read -r response

if [ "$response" = "y" ]; then
    echo ""
    ./tools/run_standardization.sh
fi
