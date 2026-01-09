#!/usr/bin/env python3
"""
Script de extracción de IoCs desde archivos PCAP
Genera: IPs, dominios, URLs, User-Agents, hashes de certificados
"""

import sys
import json
import hashlib
from scapy.all import *
from collections import defaultdict
from datetime import datetime

class IoC_Extractor:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.iocs = {
            'ips': defaultdict(int),
            'domains': set(),
            'urls': set(),
            'user_agents': set(),
            'certificates': set(),
            'suspicious_ports': defaultdict(int),
            'connections': []
        }
    
    def analyze_pcap(self):
        """Analizar el archivo PCAP completo"""
        print(f"[+] Analizando PCAP: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        
        for pkt in packets:
            self._extract_network_iocs(pkt)
            self._extract_http_iocs(pkt)
            self._extract_dns_iocs(pkt)
            self._extract_tls_iocs(pkt)
        
        print(f"[+] Análisis completado: {len(packets)} paquetes procesados")
    
    def _extract_network_iocs(self, pkt):
        """Extraer IPs, puertos y conexiones"""
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Contar IPs
            self.iocs['ips'][src_ip] += 1
            self.iocs['ips'][dst_ip] += 1
            
            # Registrar puertos sospechosos
            if TCP in pkt:
                dst_port = pkt[TCP].dport
                if dst_port not in [80, 443, 53]:  # Puertos comunes
                    self.iocs['suspicious_ports'][dst_port] += 1
                
                # Registrar conexiones
                self.iocs['connections'].append({
                    'src': src_ip,
                    'dst': dst_ip,
                    'port': dst_port,
                    'proto': 'TCP'
                })
    
    def _extract_http_iocs(self, pkt):
        """Extraer URLs, User-Agents y datos HTTP"""
        if Raw in pkt:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Buscar User-Agent
            if 'User-Agent:' in payload:
                lines = payload.split('\r\n')
                for line in lines:
                    if line.startswith('User-Agent:'):
                        ua = line.split(':', 1)[1].strip()
                        self.iocs['user_agents'].add(ua)
            
            # Buscar Host y Path (para reconstruir URLs)
            if 'Host:' in payload and ('GET' in payload or 'POST' in payload):
                lines = payload.split('\r\n')
                host = None
                path = None
                
                for line in lines:
                    if line.startswith('Host:'):
                        host = line.split(':', 1)[1].strip()
                    if line.startswith('GET') or line.startswith('POST'):
                        parts = line.split()
                        if len(parts) >= 2:
                            path = parts[1]
                
                if host and path:
                    url = f"http://{host}{path}"
                    self.iocs['urls'].add(url)
    
    def _extract_dns_iocs(self, pkt):
        """Extraer consultas DNS"""
        if DNS in pkt and pkt[DNS].qr == 0:  # Query (no respuesta)
            qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
            if qname.endswith('.'):
                qname = qname[:-1]
            self.iocs['domains'].add(qname)
    
    def _extract_tls_iocs(self, pkt):
        """Extraer información de certificados TLS (simplificado)"""
        # Nota: Para análisis TLS completo, usar pyshark o tshark
        pass
    
    def generate_report(self, output_file):
        """Generar informe JSON de IoCs"""
        report = {
            'metadata': {
                'pcap_file': self.pcap_file,
                'timestamp': datetime.now().isoformat(),
                'total_packets': len(rdpcap(self.pcap_file))
            },
            'iocs': {
                'ip_addresses': dict(sorted(
                    self.iocs['ips'].items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:20]),  # Top 20 IPs
                'domains': sorted(list(self.iocs['domains'])),
                'urls': sorted(list(self.iocs['urls'])),
                'user_agents': sorted(list(self.iocs['user_agents'])),
                'suspicious_ports': dict(self.iocs['suspicious_ports'])
            }
        }
        
        # Guardar JSON
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Reporte generado: {output_file}")
        
        # Imprimir resumen
        print("\n=== RESUMEN DE IoCs ===")
        print(f"IPs únicas: {len(self.iocs['ips'])}")
        print(f"Dominios: {len(self.iocs['domains'])}")
        print(f"URLs: {len(self.iocs['urls'])}")
        print(f"User-Agents: {len(self.iocs['user_agents'])}")
        print(f"Puertos sospechosos: {len(self.iocs['suspicious_ports'])}")

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <archivo.pcap> [output.json]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'iocs_report.json'
    
    extractor = IoC_Extractor(pcap_file)
    extractor.analyze_pcap()
    extractor.generate_report(output_file)

if __name__ == '__main__':
    main()
