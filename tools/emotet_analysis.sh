#!/bin/bash
#
# Análisis específico de Emotet PCAP
# Campaña: 2019-01-24 Emotet infection with spamming
#

PCAP="data/emotet/emotet-2019-01-24.pcap"
OUTPUT_DIR="analysis/network/emotet_detailed"

mkdir -p "$OUTPUT_DIR"

echo "╔═══════════════════════════════════════════╗"
echo "║   ANÁLISIS DETALLADO - EMOTET             ║"
echo "║   Campaña: 2019-01-24                     ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# === FASE 1: INFECCIÓN INICIAL ===
echo "[FASE 1] Identificando vector de infección inicial..."

# Buscar descarga de payload (Word macros → PowerShell → Emotet DLL)
echo "  [+] Buscando descargas HTTP sospechosas..."
tshark -r "$PCAP" -Y "http.request.method == GET && (http.request.uri contains \".exe\" || http.request.uri contains \".dll\" || http.request.uri contains \".bin\")" \
    -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
    > "$OUTPUT_DIR/01_initial_payload_downloads.txt"

if [ -s "$OUTPUT_DIR/01_initial_payload_downloads.txt" ]; then
    echo "  ✓ Descargas de payload encontradas:"
    cat "$OUTPUT_DIR/01_initial_payload_downloads.txt"
else
    echo "  → Buscando cualquier descarga HTTP..."
    tshark -r "$PCAP" -Y "http.request.method == GET" \
        -T fields -e http.request.uri | head -20
fi
echo ""

# User-Agents (identificar PowerShell, Windows Update malicioso, etc.)
echo "  [+] Analizando User-Agents..."
tshark -r "$PCAP" -Y "http.user_agent" \
    -T fields -e http.user_agent | sort -u \
    > "$OUTPUT_DIR/02_user_agents.txt"

echo "  ✓ User-Agents únicos:"
cat "$OUTPUT_DIR/02_user_agents.txt"
echo ""

# === FASE 2: COMUNICACIÓN C2 (COMMAND & CONTROL) ===
echo "[FASE 2] Identificando comunicación C2..."

# Peticiones POST (típicas de Emotet para C2)
echo "  [+] Analizando peticiones POST (beaconing C2)..."
tshark -r "$PCAP" -Y "http.request.method == POST" \
    -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
    > "$OUTPUT_DIR/03_c2_post_requests.txt"

echo "  ✓ Peticiones POST encontradas: $(wc -l < $OUTPUT_DIR/03_c2_post_requests.txt)"

# IPs C2 más contactadas
tshark -r "$PCAP" -Y "http.request.method == POST" \
    -T fields -e ip.dst | sort | uniq -c | sort -rn \
    > "$OUTPUT_DIR/04_c2_ips_frequency.txt"

echo "  ✓ Top IPs C2 candidatas:"
head -10 "$OUTPUT_DIR/04_c2_ips_frequency.txt"
echo ""

# Analizar periodicidad (beaconing)
echo "  [+] Detectando periodicidad en comunicaciones (beaconing)..."
tshark -r "$PCAP" -Y "http.request.method == POST" \
    -T fields -e frame.time_relative -e ip.dst \
    > "$OUTPUT_DIR/05_c2_timing.txt"

echo "  ✓ Timestamps de POST guardados para análisis de periodicidad"
echo ""

# === FASE 3: ACTIVIDAD DE SPAM (EMOTET SPAMMING) ===
echo "[FASE 3] Analizando actividad de spam..."

# Tráfico SMTP saliente
tshark -r "$PCAP" -Y "smtp" \
    -T fields -e frame.time -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter \
    > "$OUTPUT_DIR/06_smtp_activity.txt"

if [ -s "$OUTPUT_DIR/06_smtp_activity.txt" ]; then
    SMTP_LINES=$(wc -l < "$OUTPUT_DIR/06_smtp_activity.txt")
    echo "  ✓ Actividad SMTP detectada: $SMTP_LINES comandos"
    
    # Contar conexiones SMTP únicas
    SMTP_CONNECTIONS=$(tshark -r "$PCAP" -Y "smtp" -T fields -e ip.dst | sort -u | wc -l)
    echo "  ✓ Servidores SMTP contactados: $SMTP_CONNECTIONS"
    
    # Extraer comandos MAIL FROM (remitentes falsos)
    echo ""
    echo "  [+] Remitentes de spam (MAIL FROM):"
    grep -i "MAIL FROM" "$OUTPUT_DIR/06_smtp_activity.txt" | awk '{print $NF}' | sort -u | head -20
    
    # Extraer comandos RCPT TO (víctimas de spam)
    echo ""
    echo "  [+] Destinatarios de spam (RCPT TO):"
    grep -i "RCPT TO" "$OUTPUT_DIR/06_smtp_activity.txt" | awk '{print $NF}' | sort -u | head -20
else
    echo "  ✗ No se detectó actividad SMTP (revisar PCAP)"
fi
echo ""

# === FASE 4: DNS (RESOLUCIÓN DE DOMINIOS C2) ===
echo "[FASE 4] Analizando resoluciones DNS..."

# Todas las consultas DNS
tshark -r "$PCAP" -Y "dns.qry.name" \
    -T fields -e dns.qry.name | sort -u \
    > "$OUTPUT_DIR/07_dns_queries.txt"

echo "  ✓ Dominios consultados: $(wc -l < $OUTPUT_DIR/07_dns_queries.txt)"

# Frecuencia de consultas (detectar DGA)
tshark -r "$PCAP" -Y "dns.qry.name" \
    -T fields -e dns.qry.name | sort | uniq -c | sort -rn \
    > "$OUTPUT_DIR/08_dns_frequency.txt"

echo "  ✓ Dominios más consultados:"
head -10 "$OUTPUT_DIR/08_dns_frequency.txt"
echo ""

# Buscar patrones DGA (Domain Generation Algorithm)
echo "  [+] Buscando patrones DGA..."
grep -E '^[a-z0-9]{12,}\..*' "$OUTPUT_DIR/07_dns_queries.txt" \
    > "$OUTPUT_DIR/09_dga_suspects.txt"

if [ -s "$OUTPUT_DIR/09_dga_suspects.txt" ]; then
    echo "  ✓ Posibles dominios DGA:"
    head -10 "$OUTPUT_DIR/09_dga_suspects.txt"
else
    echo "  → No se detectaron patrones DGA evidentes"
fi
echo ""

# === FASE 5: ANÁLISIS DE PUERTOS Y SERVICIOS ===
echo "[FASE 5] Analizando puertos y servicios contactados..."

# Puertos de destino más usados
tshark -r "$PCAP" -T fields -e tcp.dstport \
    | grep -v '^$' | sort | uniq -c | sort -rn | head -20 \
    > "$OUTPUT_DIR/10_top_dst_ports.txt"

echo "  ✓ Top 20 puertos de destino:"
cat "$OUTPUT_DIR/10_top_dst_ports.txt"
echo ""

# === FASE 6: ESTADÍSTICAS GENERALES ===
echo "[FASE 6] Generando estadísticas generales..."

# Top IPs de destino (global)
tshark -r "$PCAP" -T fields -e ip.dst \
    | grep -v '^$' | sort | uniq -c | sort -rn | head -20 \
    > "$OUTPUT_DIR/11_top_dst_ips.txt"

echo "  ✓ Top 20 IPs de destino:"
cat "$OUTPUT_DIR/11_top_dst_ips.txt"
echo ""

# Conversaciones TCP (identificar C2 por volumen)
tshark -r "$PCAP" -q -z conv,tcp | head -20 \
    > "$OUTPUT_DIR/12_tcp_conversations.txt"

echo "  ✓ Top conversaciones TCP guardadas"
echo ""

# === FASE 7: EXTRACCIÓN DE OBJETOS HTTP ===
echo "[FASE 7] Extrayendo objetos HTTP (payloads)..."

mkdir -p "$OUTPUT_DIR/http_objects"

tshark -r "$PCAP" --export-objects "http,$OUTPUT_DIR/http_objects" 2>/dev/null

OBJECT_COUNT=$(ls -1 "$OUTPUT_DIR/http_objects" 2>/dev/null | wc -l)
echo "  ✓ Objetos HTTP extraídos: $OBJECT_COUNT"

if [ $OBJECT_COUNT -gt 0 ]; then
    echo "  → Archivos en: $OUTPUT_DIR/http_objects/"
    ls -lh "$OUTPUT_DIR/http_objects/" | head -10
fi
echo ""

# === RESUMEN FINAL ===
echo "╔═══════════════════════════════════════════╗"
echo "║   RESUMEN - EMOTET CAMPAIGN               ║"
echo "╚═══════════════════════════════════════════╝"
echo ""
echo "TIMELINE DEL ATAQUE (Hipótesis):"
echo "─────────────────────────────────────────────"
echo "1. Vector inicial: Email con documento malicioso"
echo "2. Macro ejecuta PowerShell → descarga Emotet DLL"
echo "3. Emotet establece C2 con beaconing periódico"
echo "4. Módulo de spam descargado → envío masivo"
echo ""
echo "IoCs CLAVE EXTRAÍDOS:"
echo "─────────────────────────────────────────────"

# IPs C2
if [ -f "$OUTPUT_DIR/04_c2_ips_frequency.txt" ]; then
    echo "→ IPs C2 candidatas:"
    head -5 "$OUTPUT_DIR/04_c2_ips_frequency.txt" | awk '{print "  • " $2 " (" $1 " conexiones)"}'
fi

# Dominios
if [ -f "$OUTPUT_DIR/07_dns_queries.txt" ]; then
    echo "→ Dominios únicos: $(wc -l < $OUTPUT_DIR/07_dns_queries.txt)"
fi

# SMTP
if [ -f "$OUTPUT_DIR/06_smtp_activity.txt" ]; then
    echo "→ Actividad SMTP: $(wc -l < $OUTPUT_DIR/06_smtp_activity.txt) comandos"
fi

# User-Agents
if [ -f "$OUTPUT_DIR/02_user_agents.txt" ]; then
    echo "→ User-Agents sospechosos:"
    cat "$OUTPUT_DIR/02_user_agents.txt" | sed 's/^/  • /'
fi

echo ""
echo "ARCHIVOS GENERADOS:"
echo "─────────────────────────────────────────────"
ls -1 "$OUTPUT_DIR/" | grep -v "http_objects" | sed 's/^/  → /'
echo ""
echo "Siguiente paso: Correlacionar con datos de Carnage"
echo "y mapear a MITRE ATT&CK"
echo ""
