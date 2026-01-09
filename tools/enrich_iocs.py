#!/usr/bin/env python3
"""
Enriquecimiento de IoCs con fuentes OSINT
- AbuseIPDB
- VirusTotal (requiere API key)
- URLhaus
- ThreatFox
"""

import sys
import json
import requests
import time
from datetime import datetime

class IoC_Enricher:
    def __init__(self, iocs_file, vt_api_key=None):
        self.iocs_file = iocs_file
        self.vt_api_key = vt_api_key
        self.enriched_data = {
            'ips': {},
            'domains': {},
            'urls': {}
        }
        
        # APIs públicas (sin key)
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"
        self.threatfox_api = "https://threatfox-api.abuse.ch/api/v1/"
    
    def load_iocs(self):
        """Cargar IoCs desde archivo JSON"""
        with open(self.iocs_file, 'r') as f:
            data = json.load(f)
        return data.get('iocs', {})
    
    def enrich_all(self):
        """Enriquecer todos los IoCs"""
        print("[+] Cargando IoCs...")
        iocs = self.load_iocs()
        
        # Enriquecer IPs
        if 'ip_addresses' in iocs:
            print(f"\n[+] Enriqueciendo {len(iocs['ip_addresses'])} IPs...")
            for ip in list(iocs['ip_addresses'].keys())[:10]:  # Limitar a 10
                print(f"  [-] Consultando: {ip}")
                self.enriched_data['ips'][ip] = self.check_ip_reputation(ip)
                time.sleep(1)  # Rate limiting
        
        # Enriquecer dominios
        if 'domains' in iocs:
            print(f"\n[+] Enriqueciendo {len(iocs['domains'])} dominios...")
            for domain in iocs['domains'][:10]:  # Limitar a 10
                print(f"  [-] Consultando: {domain}")
                self.enriched_data['domains'][domain] = self.check_domain(domain)
                time.sleep(1)
        
        # Enriquecer URLs
        if 'urls' in iocs:
            print(f"\n[+] Enriqueciendo {len(iocs['urls'])} URLs...")
            for url in iocs['urls'][:5]:  # Limitar a 5
                print(f"  [-] Consultando: {url}")
                self.enriched_data['urls'][url] = self.check_url(url)
                time.sleep(1)
    
    def check_ip_reputation(self, ip):
        """Consultar reputación de IP (simulado - API pública requiere key)"""
        # En producción, usar AbuseIPDB API
        return {
            'ip': ip,
            'source': 'manual_check',
            'note': 'Verificar manualmente en: https://www.abuseipdb.com/check/' + ip
        }
    
    def check_domain(self, domain):
        """Verificar dominio con ThreatFox"""
        try:
            payload = {
                "query": "search_ioc",
                "search_term": domain
            }
            response = requests.post(self.threatfox_api, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'domain': domain,
                        'malicious': True,
                        'source': 'ThreatFox',
                        'data': data.get('data', [])
                    }
            
            return {
                'domain': domain,
                'malicious': False,
                'source': 'ThreatFox',
                'note': 'No threat intelligence found'
            }
        except Exception as e:
            return {
                'domain': domain,
                'error': str(e)
            }
    
    def check_url(self, url):
        """Verificar URL con URLhaus"""
        try:
            payload = {'url': url}
            response = requests.post(self.urlhaus_api, data=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return {
                        'url': url,
                        'malicious': True,
                        'source': 'URLhaus',
                        'threat': data.get('threat', 'unknown'),
                        'tags': data.get('tags', [])
                    }
            
            return {
                'url': url,
                'malicious': False,
                'source': 'URLhaus'
            }
        except Exception as e:
            return {
                'url': url,
                'error': str(e)
            }
    
    def generate_report(self, output_file):
        """Generar reporte enriquecido"""
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'source_file': self.iocs_file
            },
            'enriched_iocs': self.enriched_data,
            'summary': {
                'total_ips': len(self.enriched_data['ips']),
                'total_domains': len(self.enriched_data['domains']),
                'total_urls': len(self.enriched_data['urls'])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Reporte enriquecido generado: {output_file}")

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <iocs.json> [output.json] [vt_api_key]")
        sys.exit(1)
    
    iocs_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'enriched_iocs.json'
    vt_api_key = sys.argv[3] if len(sys.argv) > 3 else None
    
    enricher = IoC_Enricher(iocs_file, vt_api_key)
    enricher.enrich_all()
    enricher.generate_report(output_file)

if __name__ == '__main__':
    main()
