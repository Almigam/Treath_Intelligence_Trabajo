#!/bin/bash
#
# Generación de logs Zeek usando Docker
# Malware: EMOTET
#

BASE_DIR="$HOME/ThreatIntel-Exercise"
OUTPUT_BASE="$BASE_DIR/analysis/network"

# Ajusta ESTA línea si tu estructura es distinta
PCAP_EMOTET="$BASE_DIR/data/emotet/emotet-2019-01-24.pcap"

echo "╔════════════════════════════════════════════╗"
echo "║        Zeek + Docker - EMOTET              ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# === VALIDACIÓN ===
if [ ! -f "$PCAP_EMOTET" ]; then
    echo "❌ ERROR: PCAP no encontrado"
    echo "Ruta esperada:"
    echo "  $PCAP_EMOTET"
    echo ""
    echo "👉 Solución:"
    echo "  • Verifica dónde está el PCAP"
    echo "  • Ajusta la variable PCAP_EMOTET en el script"
    exit 1
fi

echo "[+] PCAP encontrado:"
echo "    $PCAP_EMOTET"
echo ""

# === EMOTET ===
echo "[+] Generando logs Zeek para EMOTET..."

OUTPUT_EMOTET="$OUTPUT_BASE/zeek_emotet"
mkdir -p "$OUTPUT_EMOTET"

docker run --rm \
  -v "$BASE_DIR:/data" \
  -v "$OUTPUT_EMOTET:/output" \
  zeek/zeek \
  sh -c "cd /output && zeek -r /data/$(realpath --relative-to="$BASE_DIR" "$PCAP_EMOTET")"

echo ""
echo "✓ Logs Zeek generados en: $OUTPUT_EMOTET"
echo ""

# === VERIFICACIÓN ===
echo "[+] Verificando logs generados..."
ls -1 "$OUTPUT_EMOTET" | grep -E 'conn.log|http.log|dns.log|smtp.log' \
  && echo "✓ Logs principales presentes" \
  || echo "⚠️ Logs esperados no encontrados"

echo ""
echo "✔ Proceso finalizado"

