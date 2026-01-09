#!/usr/bin/env python3
"""
Consolidación, limpieza y normalización de IoCs
Combina datos de Carnage y Emotet, elimina duplicados y ruido
"""

import json
import re
import ipaddress
from collections import defaultdict
from datetime import datetime

class IoC_Consolidator:
    def __init__(self):
        self.consolidated = {
            'ips': {
                'malicious': set(),
                'suspicious': set(),
                'internal': set(),
                'legitimate': set()
            },
            'domains': {
                'malicious': set(),
                'suspicious': set(),
                'dga_candidates': set(),
                'legitimate': set()
            },
            'urls': set(),
            'user_agents': {
                'malicious': set(),
                'suspicious': set(),
                'legitimate': set()
            },
            'email_addresses': set(),
            'file_hashes': set()
        }
        
        # Listas blancas (servicios legítimos comunes)
        self.whitelist_domains = [
            'microsoft.com', 'windows.com', 'windowsupdate.com',
            'google.com', 'googleapis.com', 'gstatic.com',
            'cloudflare.com', 'amazonaws.com', 'azure.com',
            'mozilla.org', 'firefox.com'
        ]
        
        self.whitelist_ips = [
            '8.8.8.8', '8.8.4.4',  # Google DNS
            '1.1.1.1', '1.0.0.1'   # Cloudflare DNS
        ]
    
    def is_private_ip(self, ip):
        """Verificar si es IP privada"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def is_legitimate_domain(self, domain):
        """Verificar si es dominio legítimo conocido"""
        domain_lower = domain.lower()
        for whitelist in self.whitelist_domains:
            if whitelist in domain_lower:
                return True
        return False
    
    def calculate_entropy(self, string):
        """Calcular entropía de Shannon (detectar DGA)"""
        import math
        if not string:
            return 0
        
        entropy = 0
        for char in set(string):
            prob = string.count(char) / len(string)
            entropy -= prob * math.log2(prob)
        return entropy
    
    def is_dga_candidate(self, domain):
        """Detectar dominios generados algorítmicamente"""
        # Extraer solo el nombre (sin TLD)
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        name = parts[0]
        
        # Criterios DGA:
        # 1. Longitud inusual (muy largo)
        if len(name) > 15:
            # 2. Alta entropía (aleatorio)
            entropy = self.calculate_entropy(name)
            if entropy > 3.5:
                return True
            
            # 3. Pocas vocales (nombres aleatorios)
            vowels = sum(1 for c in name.lower() if c in 'aeiou')
            if vowels < len(name) * 0.2:  # Menos del 20% vocales
                return True
        
        return False
    
    def classify_user_agent(self, ua):
        """Clasificar User-Agent"""
        ua_lower = ua.lower()
        
        # User-Agents maliciosos conocidos
        malicious_patterns = [
            'powershell', 'python-requests', 'curl', 'wget',
            'scanner', 'nikto', 'nmap', 'masscan'
        ]
        
        for pattern in malicious_patterns:
            if pattern in ua_lower:
                return 'malicious'
        
        # User-Agents sospechosos
        suspicious_patterns = [
            'bot', 'crawler', 'spider',
            'windows update agent',  # Falso Windows Update
            'msie 6.0',  # IE6 obsoleto (muy sospechoso en 2019+)
            'msie 7.0'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in ua_lower:
                return 'suspicious'
        
        return 'legitimate'
    
    def load_carnage_data(self, filepath):
        """Cargar datos de Carnage"""
        print(f"[+] Cargando datos de Carnage: {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            iocs = data.get('iocs', {})
            
            # Procesar IPs
            for ip, count in iocs.get('ip_addresses', {}).items():
                if self.is_private_ip(ip):
                    self.consolidated['ips']['internal'].add(ip)
                elif ip in self.whitelist_ips:
                    self.consolidated['ips']['legitimate'].add(ip)
                elif count > 100:  # Alta frecuencia = sospechoso
                    self.consolidated['ips']['suspicious'].add(ip)
                else:
                    self.consolidated['ips']['suspicious'].add(ip)
            
            # Procesar dominios
            for domain in iocs.get('domains', []):
                if self.is_legitimate_domain(domain):
                    self.consolidated['domains']['legitimate'].add(domain)
                elif self.is_dga_candidate(domain):
                    self.consolidated['domains']['dga_candidates'].add(domain)
                else:
                    self.consolidated['domains']['suspicious'].add(domain)
            
            # Procesar URLs
            for url in iocs.get('urls', []):
                self.consolidated['urls'].add(url)
            
            # Procesar User-Agents
            for ua in iocs.get('user_agents', []):
                classification = self.classify_user_agent(ua)
                self.consolidated['user_agents'][classification].add(ua)
            
            print(f"  ✓ Carnage procesado")
            
        except Exception as e:
            print(f"  ✗ Error al cargar Carnage: {e}")
    
    def load_emotet_data(self, filepath):
        """Cargar datos de Emotet"""
        print(f"[+] Cargando datos de Emotet: {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            iocs = data.get('iocs', {})
            
            # Procesar IPs (misma lógica que Carnage)
            for ip, count in iocs.get('ip_addresses', {}).items():
                if self.is_private_ip(ip):
                    self.consolidated['ips']['internal'].add(ip)
                elif ip in self.whitelist_ips:
                    self.consolidated['ips']['legitimate'].add(ip)
                else:
                    # En Emotet, considerar maliciosos si alta frecuencia POST
                    if count > 50:
                        self.consolidated['ips']['malicious'].add(ip)
                    else:
                        self.consolidated['ips']['suspicious'].add(ip)
            
            # Procesar dominios
            for domain in iocs.get('domains', []):
                if self.is_legitimate_domain(domain):
                    self.consolidated['domains']['legitimate'].add(domain)
                elif self.is_dga_candidate(domain):
                    self.consolidated['domains']['dga_candidates'].add(domain)
                else:
                    self.consolidated['domains']['suspicious'].add(domain)
            
            # Procesar URLs
            for url in iocs.get('urls', []):
                self.consolidated['urls'].add(url)
            
            # Procesar User-Agents
            for ua in iocs.get('user_agents', []):
                classification = self.classify_user_agent(ua)
                self.consolidated['user_agents'][classification].add(ua)
            
            print(f"  ✓ Emotet procesado")
            
        except Exception as e:
            print(f"  ✗ Error al cargar Emotet: {e}")
    
    def load_text_file(self, filepath, ioc_type):
        """Cargar archivos de texto plano (tshark outputs)"""
        print(f"[+] Cargando archivo de texto: {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ioc_type == 'domain':
                    if self.is_legitimate_domain(line):
                        self.consolidated['domains']['legitimate'].add(line)
                    elif self.is_dga_candidate(line):
                        self.consolidated['domains']['dga_candidates'].add(line)
                    else:
                        self.consolidated['domains']['suspicious'].add(line)
                
                elif ioc_type == 'ip':
                    parts = line.split()
                    if parts:
                        ip = parts[-1] if len(parts) > 1 else parts[0]
                        if not self.is_private_ip(ip) and ip not in self.whitelist_ips:
                            self.consolidated['ips']['suspicious'].add(ip)
                
                elif ioc_type == 'email':
                    # Extraer emails con regex
                    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', line)
                    for email in emails:
                        self.consolidated['email_addresses'].add(email)
            
            print(f"  ✓ Archivo procesado: {len(lines)} líneas")
            
        except Exception as e:
            print(f"  ✗ Error al cargar archivo: {e}")
    
    def generate_report(self, output_file):
        """Generar reporte consolidado"""
        
        # Convertir sets a listas para JSON
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'sources': ['carnage', 'emotet']
            },
            'statistics': {
                'ips': {
                    'malicious': len(self.consolidated['ips']['malicious']),
                    'suspicious': len(self.consolidated['ips']['suspicious']),
                    'internal': len(self.consolidated['ips']['internal']),
                    'legitimate': len(self.consolidated['ips']['legitimate'])
                },
                'domains': {
                    'malicious': len(self.consolidated['domains']['malicious']),
                    'suspicious': len(self.consolidated['domains']['suspicious']),
                    'dga_candidates': len(self.consolidated['domains']['dga_candidates']),
                    'legitimate': len(self.consolidated['domains']['legitimate'])
                },
                'urls': len(self.consolidated['urls']),
                'user_agents': {
                    'malicious': len(self.consolidated['user_agents']['malicious']),
                    'suspicious': len(self.consolidated['user_agents']['suspicious']),
                    'legitimate': len(self.consolidated['user_agents']['legitimate'])
                },
                'email_addresses': len(self.consolidated['email_addresses'])
            },
            'iocs': {
                'ips': {
                    'malicious': sorted(list(self.consolidated['ips']['malicious'])),
                    'suspicious': sorted(list(self.consolidated['ips']['suspicious']))[:50],  # Limitar
                    'internal': sorted(list(self.consolidated['ips']['internal']))
                },
                'domains': {
                    'malicious': sorted(list(self.consolidated['domains']['malicious'])),
                    'suspicious': sorted(list(self.consolidated['domains']['suspicious']))[:50],
                    'dga_candidates': sorted(list(self.consolidated['domains']['dga_candidates']))
                },
                'urls': sorted(list(self.consolidated['urls']))[:50],
                'user_agents': {
                    'malicious': sorted(list(self.consolidated['user_agents']['malicious'])),
                    'suspicious': sorted(list(self.consolidated['user_agents']['suspicious']))
                },
                'email_addresses': sorted(list(self.consolidated['email_addresses']))
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Reporte consolidado generado: {output_file}")
        
        # Imprimir resumen
        print("\n" + "="*60)
        print("RESUMEN DE IOCs CONSOLIDADOS")
        print("="*60)
        print(f"\n📍 DIRECCIONES IP:")
        print(f"   • Maliciosas:    {report['statistics']['ips']['malicious']}")
        print(f"   • Sospechosas:   {report['statistics']['ips']['suspicious']}")
        print(f"   • Internas:      {report['statistics']['ips']['internal']}")
        print(f"   • Legítimas:     {report['statistics']['ips']['legitimate']}")
        
        print(f"\n🌐 DOMINIOS:")
        print(f"   • Maliciosos:    {report['statistics']['domains']['malicious']}")
        print(f"   • Sospechosos:   {report['statistics']['domains']['suspicious']}")
        print(f"   • DGA (candidatos): {report['statistics']['domains']['dga_candidates']}")
        print(f"   • Legítimos:     {report['statistics']['domains']['legitimate']}")
        
        print(f"\n🔗 URLs: {report['statistics']['urls']}")
        
        print(f"\n🤖 USER-AGENTS:")
        print(f"   • Maliciosos:    {report['statistics']['user_agents']['malicious']}")
        print(f"   • Sospechosos:   {report['statistics']['user_agents']['suspicious']}")
        print(f"   • Legítimos:     {report['statistics']['user_agents']['legitimate']}")
        
        print(f"\n📧 EMAILS: {report['statistics']['email_addresses']}")
        print("="*60 + "\n")

def main():
    consolidator = IoC_Consolidator()
    
    # Cargar datos JSON de los scripts anteriores
    consolidator.load_carnage_data('outputs/iocs/carnage_iocs.json')
    consolidator.load_emotet_data('outputs/iocs/emotet_iocs.json')
    
    # Cargar archivos de texto adicionales
    print("\n[+] Cargando archivos de texto adicionales...")
    
    # Dominios de análisis detallado
    try:
        consolidator.load_text_file('analysis/network/carnage_detailed/07_all_domains.txt', 'domain')
    except:
        pass
    
    try:
        consolidator.load_text_file('analysis/network/emotet_detailed/07_dns_queries.txt', 'domain')
    except:
        pass
    
    # Emails de SMTP
    try:
        consolidator.load_text_file('analysis/network/emotet_detailed/06_smtp_activity.txt', 'email')
    except:
        pass
    
    # Generar reporte final
    consolidator.generate_report('outputs/iocs/consolidated_iocs.json')

if __name__ == '__main__':
    main()
