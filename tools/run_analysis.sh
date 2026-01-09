#!/bin/bash
#
# Script maestro de análisis de Threat Intelligence
# Orquesta el análisis completo de Carnage + Emotet
#

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directorio base
BASE_DIR="$HOME/ThreatIntel-Exercise"
cd "$BASE_DIR" || exit 1

# Activar entorno virtual
source venv/bin/activate

echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ANÁLISIS DE THREAT INTELLIGENCE        ║${NC}"
echo -e "${GREEN}║   Carnage + Emotet PCAP Analysis         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""

# === PASO 1: ANÁLISIS DE CARNAGE ===
echo -e "${YELLOW}[PASO 1/6] Analizando PCAP de Carnage...${NC}"

if [ -f "data/carnage/carnage.pcap" ]; then
    python3 tools/extract_iocs.py data/carnage/carnage.pcap outputs/iocs/carnage_iocs.json
    python3 tools/detect_beaconing.py data/carnage/carnage.pcap outputs/iocs/carnage_beaconing.json
    
    # Análisis con tshark
    echo -e "  ${GREEN}→${NC} Extrayendo estadísticas HTTP..."
    tshark -r data/carnage/carnage.pcap -Y "http.request" \
        -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri \
        > analysis/network/carnage_http.txt
    
    echo -e "  ${GREEN}→${NC} Extrayendo consultas DNS..."
    tshark -r data/carnage/carnage.pcap -Y "dns.qry.name" \
        -T fields -e dns.qry.name -e ip.src \
        | sort -u > analysis/network/carnage_dns.txt
    
    echo -e "  ${GREEN}✓${NC} Análisis de Carnage completado"
else
    echo -e "${RED}✗ Error: carnage.pcap no encontrado${NC}"
fi

echo ""

# === PASO 2: ANÁLISIS DE EMOTET ===
echo -e "${YELLOW}[PASO 2/6] Analizando PCAP de Emotet...${NC}"

if [ -f "data/emotet/emotet-2019-01-24.pcap" ]; then
    python3 tools/extract_iocs.py data/emotet/emotet-2019-01-24.pcap outputs/iocs/emotet_iocs.json
    python3 tools/detect_beaconing.py data/emotet/emotet-2019-01-24.pcap outputs/iocs/emotet_beaconing.json
    
    # Análisis con tshark
    echo -e "  ${GREEN}→${NC} Extrayendo tráfico SMTP..."
    tshark -r data/emotet/emotet-2019-01-24.pcap -Y "smtp" \
        -T fields -e ip.src -e ip.dst -e smtp.req.command \
        > analysis/network/emotet_smtp.txt
    
    echo -e "  ${GREEN}→${NC} Extrayendo conexiones POST..."
    tshark -r data/emotet/emotet-2019-01-24.pcap -Y "http.request.method == POST" \
        -T fields -e ip.dst -e http.host -e http.request.uri \
        > analysis/network/emotet_post.txt
    
    echo -e "  ${GREEN}✓${NC} Análisis de Emotet completado"
else
    echo -e "${RED}✗ Error: emotet-2019-01-24.pcap no encontrado${NC}"
fi

echo ""

# === PASO 3: ENRIQUECIMIENTO OSINT ===
echo -e "${YELLOW}[PASO 3/6] Enriqueciendo IoCs con OSINT...${NC}"

if [ -f "outputs/iocs/carnage_iocs.json" ]; then
    python3 tools/enrich_iocs.py outputs/iocs/carnage_iocs.json outputs/iocs/carnage_enriched.json
fi

if [ -f "outputs/iocs/emotet_iocs.json" ]; then
    python3 tools/enrich_iocs.py outputs/iocs/emotet_iocs.json outputs/iocs/emotet_enriched.json
fi

echo -e "  ${GREEN}✓${NC} Enriquecimiento OSINT completado"
echo ""

# === PASO 4: ANÁLISIS ZEEK ===
echo -e "${YELLOW}[PASO 4/6] Análisis con Zeek (Network Security Monitor)...${NC}"

# Crear directorio temporal para logs Zeek
mkdir -p analysis/network/zeek_carnage
mkdir -p analysis/network/zeek_emotet

if [ -f "data/carnage/carnage.pcap" ]; then
    echo -e "  ${GREEN}→${NC} Procesando Carnage con Zeek..."
    cd analysis/network/zeek_carnage
    zeek -r ../../../data/carnage/carnage.pcap 2>/dev/null
    cd ../../../
    echo -e "  ${GREEN}✓${NC} Logs Zeek generados en: analysis/network/zeek_carnage/"
fi

if [ -f "data/emotet/emotet-2019-01-24.pcap" ]; then
    echo -e "  ${GREEN}→${NC} Procesando Emotet con Zeek..."
    cd analysis/network/zeek_emotet
    zeek -r ../../../data/emotet/emotet-2019-01-24.pcap 2>/dev/null
    cd ../../../
    echo -e "  ${GREEN}✓${NC} Logs Zeek generados en: analysis/network/zeek_emotet/"
fi

echo ""

# === PASO 5: GENERACIÓN DE ESTADÍSTICAS ===
echo -e "${YELLOW}[PASO 5/6] Generando estadísticas y resumen...${NC}"

# Crear resumen de análisis
cat > outputs/reports/analysis_summary.txt << EOF
═══════════════════════════════════════════════════════════
    RESUMEN DE ANÁLISIS - THREAT INTELLIGENCE EXERCISE
═══════════════════════════════════════════════════════════

Fecha: $(date)
Analista: [TU NOMBRE]

ARCHIVOS ANALIZADOS:
-----------------------------------------------------------
1. Carnage (TryHackMe Room)
   - PCAP: data/carnage/carnage.pcap

2. Emotet Campaign (2019-01-24)
   - PCAP: data/emotet/emotet-2019-01-24.pcap

OUTPUTS GENERADOS:
-----------------------------------------------------------
- IoCs extraídos: outputs/iocs/
- Análisis de beaconing: outputs/iocs/*_beaconing.json
- IoCs enriquecidos: outputs/iocs/*_enriched.json
- Análisis de red: analysis/network/
- Logs Zeek: analysis/network/zeek_*/

PRÓXIMOS PASOS:
-----------------------------------------------------------
1. Revisar IoCs en outputs/iocs/
2. Correlacionar patrones entre Carnage y Emotet
3. Mapear TTPs a MITRE ATT&CK
4. Generar feeds STIX/TAXII
5. Documentar hallazgos en informe final

═══════════════════════════════════════════════════════════
EOF

echo -e "  ${GREEN}✓${NC} Resumen generado en: outputs/reports/analysis_summary.txt"
echo ""

# === PASO 6: RESUMEN FINAL ===
echo -e "${YELLOW}[PASO 6/6] Análisis completado${NC}"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}ANÁLISIS COMPLETADO EXITOSAMENTE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "Revisa los siguientes directorios:"
echo -e "  ${YELLOW}→${NC} outputs/iocs/          (IoCs extraídos)"
echo -e "  ${YELLOW}→${NC} analysis/network/      (Análisis de red)"
echo -e "  ${YELLOW}→${NC} outputs/reports/       (Resúmenes)"
echo ""
echo -e "Continúa con:"
echo -e "  ${YELLOW}1.${NC} Correlación de datos"
echo -e "  ${YELLOW}2.${NC} Mapeo a MITRE ATT&CK"
echo -e "  ${YELLOW}3.${NC} Generación de feeds STIX"
echo ""
