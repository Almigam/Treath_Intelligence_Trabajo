#!/bin/bash
#
# Análisis específico de ZEUS Panda (Panda Banker)
# Dataset: Carnage
#

PCAP="$HOME/ThreatIntel-Exercise/data/carnage/carnage.pcap"
OUTPUT_DIR="analysis/network/zeus_panda_detailed"

mkdir -p "$OUTPUT_DIR"

echo "╔════════════════════════════════════════════╗"
echo "║   ANÁLISIS DETALLADO - ZEUS PANDA          ║"
echo "║   Dataset: Carnage                         ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# === FASE 1: INFECCIÓN INICIAL ===
echo "[FASE 1] Identificando infección inicial..."

echo "  [+] Buscando descargas HTTP de ejecutables..."
tshark -r "$PCAP" \
  -Y "http.request.method == GET && (http.request.uri contains \".exe\" || http.request.uri contains \".dat\")" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  > "$OUTPUT_DIR/01_initial_payload_downloads.txt"

if [ -s "$OUTPUT_DIR/01_initial_payload_downloads.txt" ]; then
    echo "  ✓ Descargas sospechosas encontradas:"
    cat "$OUTPUT_DIR/01_initial_payload_downloads.txt"
else
    echo "  → No se detectaron descargas claras de payload"
fi
echo ""

# === FASE 2: USER-AGENTS (ZEUS PANDA) ===
echo "[FASE 2] Analizando User-Agents..."

tshark -r "$PCAP" -Y "http.user_agent" \
  -T fields -e http.user_agent | sort -u \
  > "$OUTPUT_DIR/02_user_agents.txt"

echo "  ✓ User-Agents únicos:"
cat "$OUTPUT_DIR/02_user_agents.txt"
echo ""

# === FASE 3: COMUNICACIÓN C2 (ZEUS PANDA) ===
echo "[FASE 3] Identificando comunicación C2..."

echo "  [+] Buscando HTTP POST (gate.php / panel)..."
tshark -r "$PCAP" \
  -Y "http.request.method == POST" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  > "$OUTPUT_DIR/03_c2_post_requests.txt"

echo "  ✓ Peticiones POST detectadas: $(wc -l < $OUTPUT_DIR/03_c2_post_requests.txt)"
echo ""

echo "  [+] Posibles endpoints C2 (URIs)..."
awk '{print $NF}' "$OUTPUT_DIR/03_c2_post_requests.txt" \
  | sort | uniq -c | sort -rn \
  > "$OUTPUT_DIR/04_c2_uri_frequency.txt"

head -10 "$OUTPUT_DIR/04_c2_uri_frequency.txt"
echo ""

# IPs C2 más frecuentes
tshark -r "$PCAP" -Y "http.request.method == POST" \
  -T fields -e ip.dst | sort | uniq -c | sort -rn \
  > "$OUTPUT_DIR/05_c2_ips_frequency.txt"

echo "  ✓ Top IPs C2:"
head -10 "$OUTPUT_DIR/05_c2_ips_frequency.txt"
echo ""

# === FASE 4: BEACONING (TEMPORAL) ===
echo "[FASE 4] Analizando beaconing periódico..."

tshark -r "$PCAP" -Y "http.request.method == POST" \
  -T fields -e frame.time_relative -e ip.dst \
  > "$OUTPUT_DIR/06_c2_timing.txt"

echo "  ✓ Datos de timing guardados (análisis de intervalos)"
echo ""

# === FASE 5: DNS (RESOLUCIÓN C2) ===
echo "[FASE 5] Analizando DNS..."

tshark -r "$PCAP" -Y "dns.qry.name" \
  -T fields -e dns.qry.name | sort -u \
  > "$OUTPUT_DIR/07_dns_queries.txt"

echo "  ✓ Dominios únicos consultados: $(wc -l < $OUTPUT_DIR/07_dns_queries.txt)"
echo ""

tshark -r "$PCAP" -Y "dns.qry.name" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn \
  > "$OUTPUT_DIR/08_dns_frequency.txt"

echo "  ✓ Dominios más consultados:"
head -10 "$OUTPUT_DIR/08_dns_frequency.txt"
echo ""

# === FASE 6: PUERTOS Y SERVICIOS ===
echo "[FASE 6] Analizando puertos de destino..."

tshark -r "$PCAP" -T fields -e tcp.dstport \
  | grep -v '^$' | sort | uniq -c | sort -rn | head -20 \
  > "$OUTPUT_DIR/09_top_dst_ports.txt"

cat "$OUTPUT_DIR/09_top_dst_ports.txt"
echo ""

# === FASE 7: CONVERSACIONES TCP ===
echo "[FASE 7] Analizando conversaciones TCP..."

tshark -r "$PCAP" -q -z conv,tcp | head -20 \
  > "$OUTPUT_DIR/10_tcp_conversations.txt"

echo "  ✓ Conversaciones TCP guardadas"
echo ""

# === FASE 8: EXTRACCIÓN DE OBJETOS HTTP ===
echo "[FASE 8] Extrayendo objetos HTTP..."

mkdir -p "$OUTPUT_DIR/http_objects"

tshark -r "$PCAP" --export-objects "http,$OUTPUT_DIR/http_objects" 2>/dev/null

OBJECTS=$(ls "$OUTPUT_DIR/http_objects" 2>/dev/null | wc -l)
echo "  ✓ Objetos HTTP extraídos: $OBJECTS"

if [ "$OBJECTS" -gt 0 ]; then
    ls -lh "$OUTPUT_DIR/http_objects" | head -10
fi
echo ""

# === RESUMEN FINAL ===
echo "╔════════════════════════════════════════════╗"
echo "║   RESUMEN - ZEUS PANDA                     ║"
echo "╚════════════════════════════════════════════╝"
echo ""

echo "HIPÓTESIS DE ATAQUE:"
echo "────────────────────────────────────────────"
echo "1. Vector inicial: Descarga de ejecutable vía HTTP"
echo "2. Ejecución del loader Zeus Panda"
echo "3. Beaconing periódico HTTP POST a gate.php"
echo "4. Robo de credenciales bancarias"
echo ""

echo "IoCs CLAVE:"
echo "────────────────────────────────────────────"

echo "→ IPs C2:"
head -5 "$OUTPUT_DIR/05_c2_ips_frequency.txt" | awk '{print "  • " $2 " (" $1 " conexiones)"}'

echo ""
echo "→ Dominios:"
head -5 "$OUTPUT_DIR/08_dns_frequency.txt" | awk '{print "  • " $2}'

echo ""
echo "→ User-Agents:"
cat "$OUTPUT_DIR/02_user_agents.txt" | sed 's/^/  • /'

echo ""
echo "ARCHIVOS GENERADOS:"
echo "────────────────────────────────────────────"
ls -1 "$OUTPUT_DIR" | grep -v http_objects | sed 's/^/  → /'

echo ""
echo "Siguiente paso:"
echo "• Validar gate.php / panel.php"
echo "• Correlacionar IPs con feeds de Zeus Panda"
echo "• Mapear a MITRE ATT&CK (T1059, T1071.001, T1105)"
echo ""
