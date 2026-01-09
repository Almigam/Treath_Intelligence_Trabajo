#!/usr/bin/env python3
"""
Correlación de patrones entre Carnage y Emotet
Identificación de TTPs comunes y reconstrucción de timeline
"""

import json
from datetime import datetime
from collections import defaultdict

class AttackCorrelator:
    def __init__(self):
        self.carnage_data = {}
        self.emotet_data = {}
        self.beaconing_carnage = {}
        self.beaconing_emotet = {}
        
        self.correlations = {
            'common_ips': [],
            'common_domains': [],
            'common_user_agents': [],
            'common_ttps': [],
            'behavioral_patterns': []
        }
    
    def load_data(self):
        """Cargar todos los datos consolidados"""
        print("[+] Cargando datos para correlación...")
        
        # IoCs consolidados
        try:
            with open('outputs/iocs/consolidated_iocs.json', 'r') as f:
                self.consolidated = json.load(f)
            print("  ✓ IoCs consolidados cargados")
        except:
            print("  ✗ Error: consolidated_iocs.json no encontrado")
            return False
        
        # Beaconing Carnage
        try:
            with open('outputs/iocs/carnage_beaconing.json', 'r') as f:
                self.beaconing_carnage = json.load(f)
            print("  ✓ Beaconing de Carnage cargado")
        except:
            print("  ⚠ Beaconing de Carnage no disponible")
        
        # Beaconing Emotet
        try:
            with open('outputs/iocs/emotet_beaconing.json', 'r') as f:
                self.beaconing_emotet = json.load(f)
            print("  ✓ Beaconing de Emotet cargado")
        except:
            print("  ⚠ Beaconing de Emotet no disponible")
        
        return True
    
    def correlate_infrastructure(self):
        """Correlacionar infraestructura común"""
        print("\n[+] Correlacionando infraestructura...")
        
        # Comparar IPs maliciosas/sospechosas
        carnage_ips = set(self.consolidated['iocs']['ips']['malicious'] + 
                         self.consolidated['iocs']['ips']['suspicious'])
        
        # Buscar IPs comunes (en caso de compartir infraestructura)
        common_ips = []
        for ip in carnage_ips:
            # Verificar si aparece en ambos datasets
            # (Nota: Carnage y Emotet son casos diferentes, 
            # pero pueden compartir infraestructura conocida)
            pass
        
        print(f"  → IPs maliciosas/sospechosas totales: {len(carnage_ips)}")
        
        # Analizar dominios DGA
        dga_candidates = self.consolidated['iocs']['domains']['dga_candidates']
        print(f"  → Candidatos DGA detectados: {len(dga_candidates)}")
        
        if len(dga_candidates) > 0:
            self.correlations['behavioral_patterns'].append({
                'pattern': 'Domain Generation Algorithm (DGA)',
                'evidence': f'{len(dga_candidates)} dominios con características DGA',
                'severity': 'HIGH',
                'mitre_technique': 'T1568.002'
            })
    
    def correlate_beaconing(self):
        """Correlacionar patrones de beaconing"""
        print("\n[+] Analizando patrones de beaconing...")
        
        carnage_beacons = self.beaconing_carnage.get('beacons', [])
        emotet_beacons = self.beaconing_emotet.get('beacons', [])
        
        print(f"  → Beacons en Carnage: {len(carnage_beacons)}")
        print(f"  → Beacons en Emotet: {len(emotet_beacons)}")
        
        # Analizar características de beaconing
        if carnage_beacons:
            for beacon in carnage_beacons[:3]:
                self.correlations['behavioral_patterns'].append({
                    'pattern': 'C2 Beaconing',
                    'source': 'Carnage',
                    'destination': f"{beacon['destination']}:{beacon['port']}",
                    'interval': f"{beacon['mean_interval']}s",
                    'confidence': beacon['score'],
                    'severity': 'CRITICAL',
                    'mitre_technique': 'T1071.001'
                })
        
        if emotet_beacons:
            for beacon in emotet_beacons[:3]:
                self.correlations['behavioral_patterns'].append({
                    'pattern': 'C2 Beaconing',
                    'source': 'Emotet',
                    'destination': f"{beacon['destination']}:{beacon['port']}",
                    'interval': f"{beacon['mean_interval']}s",
                    'confidence': beacon['score'],
                    'severity': 'CRITICAL',
                    'mitre_technique': 'T1071.001'
                })
    
    def identify_ttps(self):
        """Identificar TTPs comunes"""
        print("\n[+] Identificando TTPs...")
        
        ttps = []
        
        # User-Agents maliciosos (Living off the Land)
        malicious_uas = self.consolidated['iocs']['user_agents']['malicious']
        
        for ua in malicious_uas:
            if 'powershell' in ua.lower():
                ttps.append({
                    'technique': 'T1059.001',
                    'name': 'PowerShell',
                    'evidence': f'User-Agent: {ua}',
                    'tactic': 'Execution'
                })
            
            if 'python' in ua.lower() or 'curl' in ua.lower() or 'wget' in ua.lower():
                ttps.append({
                    'technique': 'T1105',
                    'name': 'Ingress Tool Transfer',
                    'evidence': f'User-Agent: {ua}',
                    'tactic': 'Command and Control'
                })
        
        # SMTP (Lateral Movement / Collection)
        if len(self.consolidated['iocs']['email_addresses']) > 0:
            ttps.append({
                'technique': 'T1114',
                'name': 'Email Collection',
                'evidence': f"{len(self.consolidated['iocs']['email_addresses'])} emails detectados",
                'tactic': 'Collection'
            })
            
            ttps.append({
                'technique': 'T1071.003',
                'name': 'Mail Protocols',
                'evidence': 'Actividad SMTP detectada',
                'tactic': 'Command and Control'
            })
        
        # DGA (Dynamic Resolution)
        if len(self.consolidated['iocs']['domains']['dga_candidates']) > 0:
            ttps.append({
                'technique': 'T1568.002',
                'name': 'Domain Generation Algorithms',
                'evidence': f"{len(self.consolidated['iocs']['domains']['dga_candidates'])} dominios DGA",
                'tactic': 'Command and Control'
            })
        
        # Application Layer Protocol (HTTP/HTTPS)
        ttps.append({
            'technique': 'T1071.001',
            'name': 'Web Protocols',
            'evidence': 'Comunicación HTTP/HTTPS para C2',
            'tactic': 'Command and Control'
        })
        
        self.correlations['common_ttps'] = ttps
        
        print(f"  ✓ {len(ttps)} TTPs identificados")
    
    def reconstruct_kill_chain(self):
        """Reconstruir la Kill Chain del ataque"""
        print("\n[+] Reconstruyendo Kill Chain...")
        
        kill_chain = {
            'phases': []
        }
        
        # Fase 1: Initial Access (Phishing presumido)
        kill_chain['phases'].append({
            'phase': '1. Initial Access',
            'mitre_tactic': 'TA0001',
            'techniques': ['T1566.001 - Spearphishing Attachment'],
            'evidence': [
                'Emotet típicamente llega vía email con documento malicioso',
                'Carnage muestra descarga de payload posterior a ejecución'
            ],
            'iocs': []
        })
        
        # Fase 2: Execution
        kill_chain['phases'].append({
            'phase': '2. Execution',
            'mitre_tactic': 'TA0002',
            'techniques': ['T1059.001 - PowerShell', 'T1204.002 - Malicious File'],
            'evidence': [
                f"User-Agents maliciosos detectados: {len(self.consolidated['iocs']['user_agents']['malicious'])}",
                'Macro de Office ejecuta PowerShell (comportamiento típico Emotet)'
            ],
            'iocs': self.consolidated['iocs']['user_agents']['malicious']
        })
        
        # Fase 3: Persistence (implícito)
        kill_chain['phases'].append({
            'phase': '3. Persistence',
            'mitre_tactic': 'TA0003',
            'techniques': ['T1547 - Boot/Logon Autostart'],
            'evidence': [
                'Emotet establece persistencia vía registro o tareas programadas',
                'Beaconing continuo indica persistencia exitosa'
            ],
            'iocs': []
        })
        
        # Fase 4: Command and Control
        c2_iocs = []
        if self.beaconing_carnage.get('beacons'):
            for beacon in self.beaconing_carnage['beacons'][:5]:
                c2_iocs.append(f"{beacon['destination']}:{beacon['port']}")
        
        if self.beaconing_emotet.get('beacons'):
            for beacon in self.beaconing_emotet['beacons'][:5]:
                c2_iocs.append(f"{beacon['destination']}:{beacon['port']}")
        
        kill_chain['phases'].append({
            'phase': '4. Command and Control',
            'mitre_tactic': 'TA0011',
            'techniques': [
                'T1071.001 - Web Protocols',
                'T1568.002 - Domain Generation Algorithms',
                'T1573 - Encrypted Channel'
            ],
            'evidence': [
                f"Beaconing detectado: intervalos regulares de comunicación",
                f"DGA: {len(self.consolidated['iocs']['domains']['dga_candidates'])} dominios candidatos",
                f"Comunicación HTTPS cifrada"
            ],
            'iocs': c2_iocs
        })
        
        # Fase 5: Collection (SMTP = Spamming module)
        kill_chain['phases'].append({
            'phase': '5. Collection',
            'mitre_tactic': 'TA0009',
            'techniques': ['T1114 - Email Collection'],
            'evidence': [
                f"Direcciones de email recolectadas: {len(self.consolidated['iocs']['email_addresses'])}",
                'Actividad SMTP indica módulo de spam activo'
            ],
            'iocs': list(self.consolidated['iocs']['email_addresses'])[:10]
        })
        
        # Fase 6: Impact (Spam distribution)
        kill_chain['phases'].append({
            'phase': '6. Impact',
            'mitre_tactic': 'TA0040',
            'techniques': ['T1499 - Endpoint Denial of Service (via spam)'],
            'evidence': [
                'Emotet distribuye spam masivo',
                'Sistema comprometido usado como bot de spam'
            ],
            'iocs': []
        })
        
        return kill_chain
    
    def generate_report(self):
        """Generar reporte de correlación"""
        
        # Reconstruir kill chain
        kill_chain = self.reconstruct_kill_chain()
        
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'analysis': 'Correlation between Carnage and Emotet campaigns'
            },
            'summary': {
                'behavioral_patterns': len(self.correlations['behavioral_patterns']),
                'ttps_identified': len(self.correlations['common_ttps']),
                'kill_chain_phases': len(kill_chain['phases'])
            },
            'behavioral_patterns': self.correlations['behavioral_patterns'],
            'ttps': self.correlations['common_ttps'],
            'kill_chain': kill_chain
        }
        
        with open('analysis/correlation/attack_correlation.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print("\n" + "="*70)
        print("REPORTE DE CORRELACIÓN GENERADO")
        print("="*70)
        print(f"\n📊 ESTADÍSTICAS:")
        print(f"   • Patrones conductuales: {report['summary']['behavioral_patterns']}")
        print(f"   • TTPs identificados: {report['summary']['ttps_identified']}")
        print(f"   • Fases Kill Chain: {report['summary']['kill_chain_phases']}")
        
        print(f"\n🎯 KILL CHAIN RECONSTRUIDA:")
        for phase in kill_chain['phases']:
            print(f"\n   {phase['phase']}")
            print(f"      Tácticas: {phase['mitre_tactic']}")
            print(f"      Técnicas: {', '.join(phase['techniques'])}")
        
        print(f"\n📁 Reporte guardado en: analysis/correlation/attack_correlation.json")
        print("="*70 + "\n")

def main():
    # Crear directorio de correlación
    import os
    os.makedirs('analysis/correlation', exist_ok=True)
    
    correlator = AttackCorrelator()
    
    if not correlator.load_data():
        print("\n[!] Error: No se pudieron cargar los datos")
        return
    
    correlator.correlate_infrastructure()
    correlator.correlate_beaconing()
    correlator.identify_ttps()
    correlator.generate_report()

if __name__ == '__main__':
    main()
