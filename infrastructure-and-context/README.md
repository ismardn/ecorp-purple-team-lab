# Architecture, systèmes et télémétrie : construction du lab E Corp

Cette section documente les fondations techniques du projet E Corp. Plutôt que de présenter un environnement préconfiguré, ces documents détaillent le processus de construction complet : du routage réseau jusqu'au déploiement du SIEM, en passant par l'ingénierie des vulnérabilités (dette technique, configuration Active Directory) nécessaires pour justifier le scénario d'attaque.

## Table des matières (architecture et télémétrie)

La documentation est structurée de manière logique, de la fondation réseau jusqu'à la résolution des défis d'ingénierie. Cliquez sur les liens ci-dessous pour accéder à l'analyse technique détaillée de chaque étape de construction :

| Phase | Fichier d'analyse | Description de l'objectif | Concepts clés |
| :---: | :--- | :--- | :--- |
| **01** | [Architecture réseau et routage](./01-network-and-routing-architecture.md) | Segmentation hyperviseur (DMZ, LAN, SOC), plan d'adressage IP et règles d'exposition (port forwarding) pfSense. | `VLANs`, `pfSense`, `NAT`, `DHCP` |
| **02** | [Systèmes et ingénierie du scénario](./02-systems-and-attack-surface.md) | Détail de la configuration système et ingénierie du scénario : simulation des contraintes d'entreprise et de la dette technique pour justifier la surface d'attaque. | `Active Directory`, `Systemd`, `WinRM`, `SPN` |
| **03** | [Déploiement du SOC et télémétrie](./03-soc-and-telemetry-deployment.md) | Mise en place de la stack Elastic, déploiement de Sysmon, GPO d'audit et ingestion des logs réseau Suricata. | `Elastic SIEM`, `Sysmon`, `Suricata`, `Event 4104` |
| **04** | [Troubleshooting et leçons apprises](./04-troubleshooting-and-lessons-learned.md) | Résolution des défis d'ingénierie : limites UDP, migration de SIEM, et contournement des défenses EDR. | `Syslog-ng`, `Architecture`, `OpSec` |