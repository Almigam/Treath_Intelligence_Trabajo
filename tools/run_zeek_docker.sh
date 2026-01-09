cd ~/ThreatIntel-Exercise

# === 1. ANÁLISIS HTTP ===
echo "[+] Extrayendo peticiones HTTP..."

# Peticiones GET
tshark -r data/carnage/carnage.pcap -Y "http.request.method == GET" \
    -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
    > analysis/network/carnage_http_get.csv

# Peticiones POST (posible C2 o exfiltración)
tshark -r data/carnage/carnage.pcap -Y "http.request.method == POST" \
    -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
    > analysis/network/carnage_http_post.csv

# User-Agents (detectar automatización)
tshark -r data/carnage/carnage.pcap -Y "http.user_agent" \
    -T fields -e http.user_agent | sort -u \
    > analysis/network/carnage_user_agents.txt

echo "[+] Archivos HTTP extraídos"

# === 2. ANÁLISIS DNS ===
echo "[+] Extrayendo consultas DNS..."

# Todas las consultas DNS
tshark -r data/carnage/carnage.pcap -Y "dns.qry.name" \
    -T fields -e frame.time -e ip.src -e dns.qry.name \
    > analysis/network/carnage_dns_queries.csv

# Buscar dominios únicos
tshark -r data/carnage/carnage.pcap -Y "dns.qry.name" \
    -T fields -e dns.qry.name | sort -u \
    > analysis/network/carnage_domains.txt

# Buscar patrones DGA (dominios aleatorios)
tshark -r data/carnage/carnage.pcap -Y "dns.qry.name" \
    -T fields -e dns.qry.name | grep -E '^[a-z0-9]{20,}' \
    > analysis/network/carnage_dga_suspects.txt

echo "[+] Archivos DNS extraídos"

# === 3. ANÁLISIS SMTP ===
echo "[+] Extrayendo tráfico SMTP..."

# Comandos SMTP
tshark -r data/carnage/carnage.pcap -Y "smtp" \
    -T fields -e frame.time -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter \
    > analysis/network/carnage_smtp.csv

# Extraer asuntos de emails (si existen)
tshark -r data/carnage/carnage.pcap -Y "smtp" \
    -T fields -e smtp.data.fragment | grep -i "subject:" \
    > analysis/network/carnage_smtp_subjects.txt

echo "[+] Archivos SMTP extraídos"

# === 4. ESTADÍSTICAS GENERALES ===
echo "[+] Generando estadísticas..."

# Top 20 IPs de destino
tshark -r data/carnage/carnage.pcap -T fields -e ip.dst \
    | sort | uniq -c | sort -rn | head -20 \
    > analysis/network/carnage_top_dst_ips.txt

# Top 20 IPs de origen
tshark -r data/carnage/carnage.pcap -T fields -e ip.src \
    | sort | uniq -c | sort -rn | head -20 \
    > analysis/network/carnage_top_src_ips.txt

# Conversaciones TCP (identificar C2 por volumen)
tshark -r data/carnage/carnage.pcap -q -z conv,tcp \
    > analysis/network/carnage_tcp_conversations.txt

echo "[+] Estadísticas generadas"
