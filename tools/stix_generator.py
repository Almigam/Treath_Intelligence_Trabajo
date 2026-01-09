#!/usr/bin/env python3
"""
Generador de STIX 2.1 Bundle
Convierte IoCs y TTPs en formato STIX estándar para compartir
"""

import json
from datetime import datetime, timezone
from stix2 import (
    Bundle, Indicator, Malware, ThreatActor, AttackPattern,
    Relationship, Identity, Report
)

# Timestamp UTC correcto y compatible STIX
UTC_NOW = lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class STIX_Generator:
    def __init__(self):
        self.objects = []
        self.consolidated_iocs = {}
        self.mitre_mapping = {}
        self.correlation_data = {}

        self.identity = Identity(
            name="Threat Intelligence Exercise - EUNEIZ",
            identity_class="organization",
            description="Análisis de inteligencia de amenazas - Carnage + Emotet Campaign"
        )
        self.objects.append(self.identity)

    def load_data(self):
        print("[+] Cargando datos procesados...")

        with open("outputs/iocs/consolidated_iocs.json") as f:
            self.consolidated_iocs = json.load(f)
        print("  ✓ IoCs consolidados cargados")

        with open("analysis/mitre/mitre_mapping.json") as f:
            self.mitre_mapping = json.load(f)
        print("  ✓ Mapeo MITRE cargado")

        with open("analysis/correlation/attack_correlation.json") as f:
            self.correlation_data = json.load(f)
        print("  ✓ Datos de correlación cargados")

    def create_malware_objects(self):
        print("\n[+] Creando objetos Malware...")

        emotet = Malware(
            name="Emotet",
            is_family=True,
            malware_types=["trojan", "backdoor", "spyware"],
            aliases=["Geodo", "Heodo"],
            first_seen="2014-01-01T00:00:00Z",
            labels=["emotet", "banking-trojan", "botnet"],
            description="Emotet es un troyano bancario modular distribuido vía phishing."
        )

        cobalt_strike = Malware(
            name="Cobalt Strike",
            is_family=True,
            malware_types=["backdoor", "remote-access-trojan"],
            labels=["cobalt-strike", "c2-framework"],
            description="Framework de C2 usado por actores maliciosos."
        )

        self.objects.extend([emotet, cobalt_strike])
        print("  ✓ 2 objetos Malware creados")
        return emotet, cobalt_strike

    def create_threat_actor(self):
        print("\n[+] Creando objeto Threat Actor...")

        actor = ThreatActor(
            name="TA505 / Emotet Operators",
            threat_actor_types=["crime-syndicate"],
            aliases=["TA505", "Dridex Gang"],
            sophistication="advanced",
            resource_level="organization",
            primary_motivation="financial-gain",
            labels=["emotet", "ta505"],
            description="Grupo criminal responsable de campañas Emotet."
        )

        self.objects.append(actor)
        print("  ✓ Threat Actor creado")
        return actor

    def create_attack_patterns(self):
        print("\n[+] Creando Attack Patterns (MITRE ATT&CK)...")

        attack_patterns = []
        techniques = self.mitre_mapping.get("techniques_detail", {})

        for tech_id, tech in techniques.items():
            if tech.get("detection_confidence") in ["HIGH", "MEDIUM"]:
                pattern = AttackPattern(
                    name=tech["name"],
                    description=tech.get("description", ""),
                    external_references=[{
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                    }],
                    x_mitre_detection="\n".join(tech.get("evidence", [])),
                    allow_custom=True
                )
                self.objects.append(pattern)
                attack_patterns.append(pattern)

        print(f"  ✓ {len(attack_patterns)} Attack Patterns creados")
        return attack_patterns

    def create_indicators(self):
        print("\n[+] Creando Indicators...")

        indicators = []
        iocs = self.consolidated_iocs.get("iocs", {})

        for ip in iocs.get("ips", {}).get("malicious", [])[:20]:
            indicator = Indicator(
                name=f"Malicious IP: {ip}",
                description="Dirección IP asociada a C2",
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from=UTC_NOW(),
                labels=["malicious-activity", "c2"],
                indicator_types=["malicious-activity"]
            )
            self.objects.append(indicator)
            indicators.append(indicator)

        print(f"  ✓ {len(indicators)} Indicators creados")
        return indicators

    def create_relationships(self, emotet, actor, attack_patterns, indicators):
        print("\n[+] Creando Relationships...")

        relationships = []

        relationships.append(Relationship(
            relationship_type="uses",
            source_ref=actor.id,
            target_ref=emotet.id,
            description="TA505 utiliza Emotet"
        ))

        for pattern in attack_patterns[:10]:
            relationships.append(Relationship(
                relationship_type="uses",
                source_ref=emotet.id,
                target_ref=pattern.id
            ))

        for indicator in indicators[:50]:
            relationships.append(Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=emotet.id
            ))

        self.objects.extend(relationships)
        print(f"  ✓ {len(relationships)} Relationships creadas")

    def create_report(self):
        print("\n[+] Creando Report...")

        report = Report(
            name="Threat Intelligence Report - Emotet / Carnage",
            description="Reporte STIX completo de Emotet y dataset Carnage.",
            published=UTC_NOW(),
            report_types=["threat-report"],
            object_refs=[obj.id for obj in self.objects if hasattr(obj, "id")],
            labels=["emotet", "carnage"]
        )

        self.objects.append(report)
        print("  ✓ Report creado")

    def generate_bundle(self):
        print("\n[+] Generando STIX 2.1 Bundle...")

        # ✅ PERMITIR CONTENIDO CUSTOM EN EL BUNDLE
        bundle = Bundle(
            objects=self.objects,
            allow_custom=True
        )

        with open("outputs/stix/threat_intelligence_bundle.json", "w") as f:
            f.write(bundle.serialize(pretty=True))

        print(f"  ✓ Bundle generado con {len(self.objects)} objetos")


def main():
    import os
    os.makedirs("outputs/stix", exist_ok=True)

    generator = STIX_Generator()
    generator.load_data()

    emotet, _ = generator.create_malware_objects()
    actor = generator.create_threat_actor()
    patterns = generator.create_attack_patterns()
    indicators = generator.create_indicators()

    generator.create_relationships(emotet, actor, patterns, indicators)
    generator.create_report()
    generator.generate_bundle()


if __name__ == "__main__":
    main()
