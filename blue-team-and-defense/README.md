# Blue Team : détection, investigation et remédiation (DFIR)

Cette section constitue le volet défensif (Blue Team) de l'approche Purple Team du projet E Corp. Elle a pour but d'analyser la Kill Chain détaillée dans la section Red Team du point de vue des défenseurs. Plutôt que de se limiter à un simple constat de compromission, cette documentation décortique la télémétrie capturée, identifie les angles morts du SIEM et propose un plan de remédiation architectural et systémique.

## Table des matières (phases d'investigation)

L'investigation suit une méthodologie structurée, allant de l'évaluation macroscopique de la détection jusqu'au durcissement de l'infrastructure. Cliquez sur les liens ci-dessous pour accéder à l'analyse technique détaillée :

| Phase | Fichier d'analyse | Description de l'objectif | Concepts clés |
| :---: | :--- | :--- | :--- |
| **01** | [Matrice de couverture de détection](./01-detection-coverage-matrix.md) | Évaluation exhaustive de la visibilité du SOC (SIEM) face aux 5 phases de l'attaque. Identification des alertes franches, des effets de bord et des angles morts (cécité WinRM / DCSync). | `MITRE ATT&CK`, `SIEM`, `Coverage Matrix` |
| **02** | [Analyse de la détection réseau](./02-network-intrusion-detection.md) | Investigation forensique des alertes Suricata : extraction de l'IoC Log4Shell, détection du tunneling (Chisel) et désanonymisation de l'attaquant via décodage NTLMSSP. | `Suricata`, `DPI`, `Traffic Analysis`, `IoC` |
| **03** | [Télémétrie système et investigation](./03-endpoint-and-ad-telemetry.md) | Analyse des journaux locaux pour contrer les techniques d'évasion : interception de l'injection mémoire *fileless* et matérialisation des attaques Kerberoasting / DCSync. | `Sysmon`, `Event 4104`, `Event 4662`, `DFIR` |
| **04** | [Plan de remédiation et durcissement](./04-remediation-and-hardening.md) | Bilan des vulnérabilités architecturales (aberration pfSense) et proposition d'un plan d'action priorisé : micro-segmentation, conteneurisation, hygiène AD et Active Response. | `Hardening`, `Zero Trust`, `Active Response` |