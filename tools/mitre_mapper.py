#!/usr/bin/env python3
"""
Mapeo completo de TTPs a MITRE ATT&CK Framework
Genera matriz de técnicas y navegador ATT&CK
"""

import json
from datetime import datetime

class MITRE_Mapper:
    def __init__(self):
        # Mapeo completo de técnicas detectadas
        self.techniques = {
            # INITIAL ACCESS
            'T1566.001': {
                'name': 'Phishing: Spearphishing Attachment',
                'tactic': 'Initial Access',
                'tactic_id': 'TA0001',
                'description': 'Email malicioso con documento adjunto (macro)',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Emotet típicamente distribuido vía email con documentos Office maliciosos',
                    'Macro ejecuta PowerShell para descargar payload'
                ]
            },
            
            # EXECUTION
            'T1059.001': {
                'name': 'Command and Scripting Interpreter: PowerShell',
                'tactic': 'Execution',
                'tactic_id': 'TA0002',
                'description': 'Uso de PowerShell para ejecutar comandos maliciosos',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'User-Agent "PowerShell" detectado en tráfico HTTP',
                    'Descarga de payloads vía PowerShell típica de Emotet'
                ]
            },
            'T1204.002': {
                'name': 'User Execution: Malicious File',
                'tactic': 'Execution',
                'tactic_id': 'TA0002',
                'description': 'Usuario ejecuta archivo malicioso',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Documento Office con macro maliciosa',
                    'Usuario debe habilitar macros para ejecutar payload'
                ]
            },
            
            # PERSISTENCE
            'T1547': {
                'name': 'Boot or Logon Autostart Execution',
                'tactic': 'Persistence',
                'tactic_id': 'TA0003',
                'description': 'Persistencia vía autoarranque en sistema',
                'detection_confidence': 'MEDIUM',
                'evidence': [
                    'Emotet establece persistencia vía registro de Windows',
                    'Beaconing continuo indica persistencia exitosa'
                ]
            },
            
            # DEFENSE EVASION
            'T1027': {
                'name': 'Obfuscated Files or Information',
                'tactic': 'Defense Evasion',
                'tactic_id': 'TA0005',
                'description': 'Ofuscación de código malicioso',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'PowerShell con comandos ofuscados (-EncodedCommand)',
                    'Payload cifrado en memoria'
                ]
            },
            'T1140': {
                'name': 'Deobfuscate/Decode Files or Information',
                'tactic': 'Defense Evasion',
                'tactic_id': 'TA0005',
                'description': 'Decodificación de payload en memoria',
                'detection_confidence': 'MEDIUM',
                'evidence': [
                    'PowerShell decodifica y ejecuta payload',
                    'Carga reflectiva de DLL en memoria (fileless)'
                ]
            },
            
            # CREDENTIAL ACCESS
            'T1003': {
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'tactic_id': 'TA0006',
                'description': 'Robo de credenciales (capacidad de Emotet)',
                'detection_confidence': 'LOW',
                'evidence': [
                    'Emotet tiene módulos para robo de credenciales',
                    'No evidencia directa en PCAP (ocurre en endpoint)'
                ]
            },
            
            # DISCOVERY
            'T1083': {
                'name': 'File and Directory Discovery',
                'tactic': 'Discovery',
                'tactic_id': 'TA0007',
                'description': 'Enumeración de archivos para robo de emails',
                'detection_confidence': 'MEDIUM',
                'evidence': [
                    'Emotet busca archivos de Outlook para robar contactos',
                    'Preparación para módulo de spam'
                ]
            },
            
            # COLLECTION
            'T1114': {
                'name': 'Email Collection',
                'tactic': 'Collection',
                'tactic_id': 'TA0009',
                'description': 'Recolección de direcciones de email',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Múltiples direcciones de email en tráfico SMTP',
                    'Recolección para posterior campaña de spam'
                ]
            },
            
            # COMMAND AND CONTROL
            'T1071.001': {
                'name': 'Application Layer Protocol: Web Protocols',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Uso de HTTP/HTTPS para comunicación C2',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Beaconing periódico detectado vía HTTP/HTTPS',
                    'Comunicación regular con servidores C2'
                ]
            },
            'T1071.003': {
                'name': 'Application Layer Protocol: Mail Protocols',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Uso de SMTP para exfiltración/spam',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Tráfico SMTP saliente masivo detectado',
                    'Bot de spam activo'
                ]
            },
            'T1568.002': {
                'name': 'Dynamic Resolution: Domain Generation Algorithms',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Uso de DGA para localizar servidores C2',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Dominios con alta entropía detectados',
                    'Patrón típico de DGA en consultas DNS'
                ]
            },
            'T1573': {
                'name': 'Encrypted Channel',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Comunicación C2 cifrada vía HTTPS',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Tráfico HTTPS para C2',
                    'Certificados TLS observados'
                ]
            },
            'T1105': {
                'name': 'Ingress Tool Transfer',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Descarga de herramientas/módulos adicionales',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Descarga de payloads adicionales vía HTTP',
                    'Emotet descarga módulos (spam, robo de credenciales)'
                ]
            },
            
            # IMPACT
            'T1499': {
                'name': 'Endpoint Denial of Service',
                'tactic': 'Impact',
                'tactic_id': 'TA0040',
                'description': 'Sistema comprometido usado para spam masivo',
                'detection_confidence': 'HIGH',
                'evidence': [
                    'Volumen masivo de conexiones SMTP',
                    'Sistema actúa como bot de spam'
                ]
            }
        }
        
        self.tactics_summary = {}
    
    def generate_matrix(self):
        """Generar matriz de técnicas por táctica"""
        print("[+] Generando matriz MITRE ATT&CK...")
        
        tactics = {}
        
        for tech_id, tech_data in self.techniques.items():
            tactic = tech_data['tactic']
            tactic_id = tech_data['tactic_id']
            
            if tactic not in tactics:
                tactics[tactic] = {
                    'id': tactic_id,
                    'techniques': []
                }
            
            tactics[tactic]['techniques'].append({
                'id': tech_id,
                'name': tech_data['name'],
                'confidence': tech_data['detection_confidence']
            })
        
        self.tactics_summary = tactics
        print(f"  ✓ {len(tactics)} tácticas mapeadas")
        print(f"  ✓ {len(self.techniques)} técnicas identificadas")
    
    def generate_navigator_layer(self):
        """Generar capa para ATT&CK Navigator"""
        print("\n[+] Generando capa ATT&CK Navigator...")
        
        techniques_list = []
        
        for tech_id, tech_data in self.techniques.items():
            # Score basado en confianza
            score_map = {
                'HIGH': 3,
                'MEDIUM': 2,
                'LOW': 1
            }
            
            techniques_list.append({
                'techniqueID': tech_id,
                'tactic': tech_data['tactic'].lower().replace(' ', '-'),
                'color': '',
                'comment': '; '.join(tech_data['evidence']),
                'enabled': True,
                'metadata': [],
                'score': score_map.get(tech_data['detection_confidence'], 1)
            })
        
        layer = {
            'name': 'Carnage + Emotet Campaign Analysis',
            'versions': {
                'attack': '13',
                'navigator': '4.8.1',
                'layer': '4.4'
            },
            'domain': 'enterprise-attack',
            'description': 'TTPs identificados en análisis de Carnage (TryHackMe) y campaña Emotet 2019-01-24',
            'filters': {
                'platforms': ['windows']
            },
            'sorting': 3,
            'layout': {
                'layout': 'side',
                'showID': True,
                'showName': True
            },
            'hideDisabled': False,
            'techniques': techniques_list,
            'gradient': {
                'colors': [
                    '#ffffff',
                    '#ff6666'
                ],
                'minValue': 0,
                'maxValue': 3
            },
            'legendItems': [
                {
                    'label': 'HIGH Confidence',
                    'color': '#ff6666'
                },
                {
                    'label': 'MEDIUM Confidence',
                    'color': '#ffcc66'
                },
                {
                    'label': 'LOW Confidence',
                    'color': '#ffff99'
                }
            ],
            'metadata': [
                {
                    'name': 'Analyst',
                    'value': 'Threat Intelligence Exercise'
                },
                {
                    'name': 'Date',
                    'value': datetime.now().strftime('%Y-%m-%d')
                }
            ]
        }
        
        with open('analysis/mitre/attack_navigator_layer.json', 'w') as f:
            json.dump(layer, f, indent=2)
        
        print(f"  ✓ Capa Navigator generada: analysis/mitre/attack_navigator_layer.json")
        print(f"  → Importar en: https://mitre-attack.github.io/attack-navigator/")
    
    def generate_report(self):
        """Generar reporte completo de mapeo MITRE"""
        
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'framework': 'MITRE ATT&CK v13',
                'campaigns': ['Carnage', 'Emotet 2019-01-24']
            },
            'summary': {
                'total_tactics': len(self.tactics_summary),
                'total_techniques': len(self.techniques),
                'high_confidence': len([t for t in self.techniques.values() if t['detection_confidence'] == 'HIGH']),
                'medium_confidence': len([t for t in self.techniques.values() if t['detection_confidence'] == 'MEDIUM']),
                'low_confidence': len([t for t in self.techniques.values() if t['detection_confidence'] == 'LOW'])
            },
            'tactics': self.tactics_summary,
            'techniques_detail': self.techniques
        }
        
        with open('analysis/mitre/mitre_mapping.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generar reporte en texto
        self._generate_text_report()
        
        print("\n" + "="*70)
        print("MAPEO MITRE ATT&CK COMPLETADO")
        print("="*70)
        print(f"\n📊 RESUMEN:")
        print(f"   • Tácticas identificadas: {report['summary']['total_tactics']}")
        print(f"   • Técnicas totales: {report['summary']['total_techniques']}")
        print(f"   • Confianza ALTA: {report['summary']['high_confidence']}")
        print(f"   • Confianza MEDIA: {report['summary']['medium_confidence']}")
        print(f"   • Confianza BAJA: {report['summary']['low_confidence']}")
        
        print(f"\n🗺️ TÁCTICAS CUBIERTAS:")
        for tactic, data in self.tactics_summary.items():
            print(f"   • {data['id']} - {tactic}: {len(data['techniques'])} técnicas")
        
        print(f"\n📁 ARCHIVOS GENERADOS:")
        print(f"   → analysis/mitre/mitre_mapping.json")
        print(f"   → analysis/mitre/mitre_report.txt")
        print(f"   → analysis/mitre/attack_navigator_layer.json")
        print("="*70 + "\n")
    
    def _generate_text_report(self):
        """Generar reporte en texto plano"""
        
        with open('analysis/mitre/mitre_report.txt', 'w') as f:
            f.write("="*70 + "\n")
            f.write("MAPEO MITRE ATT&CK - CARNAGE + EMOTET CAMPAIGN\n")
            f.write("="*70 + "\n\n")
            
            for tactic, data in sorted(self.tactics_summary.items()):
                f.write(f"\n{data['id']} - {tactic.upper()}\n")
                f.write("-" * 70 + "\n\n")
                
                for tech in data['techniques']:
                    tech_detail = self.techniques[tech['id']]
                    
                    f.write(f"{tech['id']}: {tech['name']}\n")
                    f.write(f"Confianza: {tech['confidence']}\n")
                    f.write(f"Descripción: {tech_detail['description']}\n")
                    f.write(f"Evidencia:\n")
                    for evidence in tech_detail['evidence']:
                        f.write(f"  • {evidence}\n")
                    f.write("\n")

def main():
    import os
    os.makedirs('analysis/mitre', exist_ok=True)
    
    mapper = MITRE_Mapper()
    mapper.generate_matrix()
    mapper.generate_navigator_layer()
    mapper.generate_report()

if __name__ == '__main__':
    main()
