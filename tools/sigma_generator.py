#!/usr/bin/env python3
"""
Generador de reglas Sigma simplificado
"""

import yaml
import os
from datetime import datetime

class Sigma_Generator:
    def __init__(self):
        self.rules = []
        self.output_dir = 'outputs/sigma'
    
    def generate_powershell_rule(self):
        """Regla Sigma para PowerShell malicioso"""
        
        rule = {
            'title': 'Malicious PowerShell Encoded Command',
            'status': 'experimental',
            'description': 'Detecta PowerShell con comando codificado',
            'author': 'Threat Intelligence Exercise - EUNEIZ',
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': ['-encodedcommand', '-enc']
                },
                'condition': 'selection'
            },
            'level': 'high'
        }
        
        self.rules.append(('powershell_encoded.yml', rule))
        print("  ✓ Regla PowerShell generada")
    
    def save_rules(self):
        """Guardar reglas"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        for filename, rule in self.rules:
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, 'w') as f:
                yaml.dump(rule, f, default_flow_style=False)
        
        print(f"\n[+] {len(self.rules)} reglas Sigma generadas")
        print(f"   → {self.output_dir}/")

def main():
    generator = Sigma_Generator()
    generator.generate_powershell_rule()
    generator.save_rules()

if __name__ == '__main__':
    main()
