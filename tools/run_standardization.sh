#!/bin/bash
#
# Script maestro para estandarización de inteligencia
# Genera STIX, YARA y Sigma en un solo comando
#

BASE_DIR="$HOME/ThreatIntel-Exercise"
cd "$BASE_DIR" || exit 1

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ESTANDARIZACIÓN DE INTELIGENCIA DE AMENAZAS            ║${NC}"
echo -e "${GREEN}║   STIX 2.1 | YARA | Sigma                                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Activar entorno virtual
source venv/bin/activate

# === PASO 1: STIX 2.1 ===
echo -e "${YELLOW}[1/3] Generando STIX 2.1 Bundle...${NC}"
python3 tools/stix_generator.py

if [ $? -eq 0 ]; then
    echo -e "${GREEN}  ✓ STIX Bundle generado${NC}"
else
    echo -e "${RED}  ✗ Error al generar STIX${NC}"
fi
echo ""

# === PASO 2: YARA ===
echo -e "${YELLOW}[2/3] Generando reglas YARA...${NC}"
python3 tools/yara_generator.py

if [ $? -eq 0 ]; then
    echo -e "${GREEN}  ✓ Reglas YARA generadas${NC}"
else
    echo -e "${RED}  ✗ Error al generar YARA${NC}"
fi
echo ""

# === PASO 3: Sigma ===
echo -e "${YELLOW}[3/3] Generando reglas Sigma...${NC}"
python3 tools/sigma_generator.py

if [ $? -eq 0 ]; then
    echo -e "${GREEN}  ✓ Reglas Sigma generadas${NC}"
else
    echo -e "${RED}  ✗ Error al generar Sigma${NC}"
fi
echo ""

# === RESUMEN FINAL ===
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ESTANDARIZACIÓN COMPLETADA                              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📦 FORMATOS GENERADOS:${NC}"
echo ""
echo -e "${YELLOW}1. STIX 2.1 Bundle${NC}"
echo "   → outputs/stix/threat_intelligence_bundle.json"
echo "   • Importar en: MISP, OpenCTI, ThreatConnect"
echo "   • Validar: stix2-validator threat_intelligence_bundle.json"
echo ""
echo -e "${YELLOW}2. Reglas YARA${NC}"
echo "   → outputs/yara/threat_intelligence_rules.yar"
echo "   • Uso: yara -r threat_intelligence_rules.yar <target>"
echo "   • Integrar en: VirusTotal, YARA-X, ClamAV"
echo ""
echo -e "${YELLOW}3. Reglas Sigma${NC}"
echo "   → outputs/sigma/*.yml"
echo "   • Convertir: sigmac -t splunk regla.yml"
echo "   • Integrar en: Splunk, ELK, QRadar, Sentinel"
echo ""
echo -e "${BLUE}🔄 PRÓXIMOS PASOS:${NC}"
echo "   1. Validar STIX bundle"
echo "   2. Probar reglas YARA en muestras"
echo "   3. Convertir Sigma a formato de tu SIEM"
echo "   4. Documentar en informe final"
echo ""
