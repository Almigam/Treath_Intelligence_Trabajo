#!/usr/bin/env python3
"""
Detector de patrones de Beaconing (comunicación C2)
Analiza periodicidad, uniformidad de tamaños y destinos repetitivos
"""

import sys
import json
from scapy.all import *
from collections import defaultdict
from datetime import datetime
import statistics

class BeaconingDetector:
    def __init__(self, pcap_file, threshold=0.8):
        self.pcap_file = pcap_file
        self.threshold = threshold  # Umbral de periodicidad (0-1)
        self.connections = defaultdict(list)
        self.beacons = []
    
    def analyze(self):
        """Analizar PCAP en busca de beaconing"""
        print(f"[+] Detectando beaconing en: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        
        # Agrupar conexiones por dst_ip:dst_port
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                timestamp = float(pkt.time)
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                size = len(pkt)
                
                key = f"{dst_ip}:{dst_port}"
                self.connections[key].append({
                    'timestamp': timestamp,
                    'src': src_ip,
                    'size': size
                })
        
        # Analizar cada conexión
        for conn_key, packets_list in self.connections.items():
            if len(packets_list) >= 5:  # Mínimo 5 conexiones
                self._analyze_connection(conn_key, packets_list)
        
        print(f"[+] Beacons detectados: {len(self.beacons)}")
        return self.beacons
    
    def _analyze_connection(self, conn_key, packets_list):
        """Analizar una conexión específica"""
        # Calcular intervalos entre paquetes
        timestamps = [p['timestamp'] for p in packets_list]
        timestamps.sort()
        
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            intervals.append(interval)
        
        if not intervals:
            return
        
        # Calcular estadísticas
        mean_interval = statistics.mean(intervals)
        
        # Evitar división por cero
        if mean_interval == 0:
            return
            
        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev_interval / mean_interval  # Coeficiente de variación
        
        # Analizar tamaños de paquetes
        sizes = [p['size'] for p in packets_list]
        mean_size = statistics.mean(sizes)
        stdev_size = statistics.stdev(sizes) if len(sizes) > 1 else 0
        
        # Criterios de beaconing:
        # 1. Baja variabilidad en intervalos (CV < 0.3)
        # 2. Intervalos regulares (no muy cortos ni muy largos)
        # 3. Tamaños similares
        
        if cv < 0.3 and 5 < mean_interval < 600:  # Entre 5s y 10min
            dst_ip, dst_port = conn_key.split(':')
            
            beacon = {
                'destination': dst_ip,
                'port': dst_port,
                'connection_count': len(packets_list),
                'mean_interval': round(mean_interval, 2),
                'interval_stdev': round(stdev_interval, 2),
                'cv': round(cv, 3),
                'mean_packet_size': round(mean_size, 2),
                'size_stdev': round(stdev_size, 2),
                'score': self._calculate_score(cv, mean_interval, len(packets_list))
            }
            
            self.beacons.append(beacon)
    
    def _calculate_score(self, cv, mean_interval, count):
        """Calcular score de confianza (0-100)"""
        score = 0
        
        # Penalizar alta variabilidad
        if cv < 0.1:
            score += 40
        elif cv < 0.2:
            score += 30
        elif cv < 0.3:
            score += 20
        
        # Premiar intervalos típicos de C2 (30s - 5min)
        if 30 <= mean_interval <= 300:
            score += 30
        elif 10 <= mean_interval < 30 or 300 < mean_interval <= 600:
            score += 20
        
        # Premiar cantidad de conexiones
        if count >= 20:
            score += 30
        elif count >= 10:
            score += 20
        elif count >= 5:
            score += 10
        
        return min(score, 100)
    
    def generate_report(self, output_file):
        """Generar reporte de beacons detectados"""
        # Ordenar por score
        self.beacons.sort(key=lambda x: x['score'], reverse=True)
        
        report = {
            'metadata': {
                'pcap_file': self.pcap_file,
                'timestamp': datetime.now().isoformat(),
                'total_beacons': len(self.beacons)
            },
            'beacons': self.beacons
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Reporte generado: {output_file}")
        
        # Mostrar top 5
        print("\n=== TOP 5 BEACONS DETECTADOS ===")
        for i, beacon in enumerate(self.beacons[:5], 1):
            print(f"\n[{i}] Destino: {beacon['destination']}:{beacon['port']}")
            print(f"    Score: {beacon['score']}/100")
            print(f"    Conexiones: {beacon['connection_count']}")
            print(f"    Intervalo medio: {beacon['mean_interval']}s")
            print(f"    Coef. variación: {beacon['cv']}")

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <archivo.pcap> [output.json]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'beaconing_report.json'
    
    detector = BeaconingDetector(pcap_file)
    detector.analyze()
    detector.generate_report(output_file)

if __name__ == '__main__':
    main()
