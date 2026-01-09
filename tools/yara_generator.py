#!/usr/bin/env python3
"""
Generador de reglas YARA basadas en IoCs y patrones detectados
"""

import json
from datetime import datetime

class YARA_Generator:
    def __init__(self):
        self.rules = []
        self.consolidated_iocs = {}
    
    def load_data(self):
        """Cargar IoCs consolidados"""
        print("[+] Cargando IoCs para generación de YARA...")
        
        try:
            with open('outputs/iocs/consolidated_iocs.json', 'r') as f:
                self.consolidated_iocs = json.load(f)
            print("  ✓ IoCs cargados")
            return True
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False
    
    def generate_emotet_network_rule(self):
        """Regla YARA para detección de comunicación Emotet"""
        
        malicious_ips = self.consolidated_iocs['iocs']['ips']['malicious']
        dga_domains = self.consolidated_iocs['iocs']['domains']['dga_candidates']
        
        ip_strings = []
        for i, ip in enumerate(malicious_ips[:10], 1):
            ip_strings.append(f'$ip{i} = "{ip}"')
        
        domain_strings = []
        for i, domain in enumerate(dga_domains[:10], 1):
            domain_strings.append(f'$domain{i} = "{domain}"')
        
        rule = f'''rule Emotet_Network_Communication {{
    meta:
        description = "Detecta comunicación de red asociada a Emotet"
        author = "Threat Intelligence Exercise - EUNEIZ"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        severity = "high"
        
    strings:
        {chr(10).join('        ' + s for s in ip_strings)}
        {chr(10).join('        ' + s for s in domain_strings)}
        
    condition:
        any of them
}}
'''
        self.rules.append(rule)
        print("  ✓ Regla Emotet_Network_Communication generada")
    
    def save_rules(self):
        """Guardar reglas"""
        header = f'''/*
    YARA Rules - Threat Intelligence Exercise
    Fecha: {datetime.now().strftime('%Y-%m-%d')}
*/

'''
        
        with open('outputs/yara/threat_intelligence_rules.yar', 'w') as f:
            f.write(header + '\n\n'.join(self.rules))
        
        print(f"\n[+] {len(self.rules)} reglas YARA generadas")
        print("   → outputs/yara/threat_intelligence_rules.yar")

def main():
    import os
    os.makedirs('outputs/yara', exist_ok=True)
    
    generator = YARA_Generator()
    if not generator.load_data():
        return
    
    generator.generate_emotet_network_rule()
    generator.save_rules()

if __name__ == '__main__':
    main()
