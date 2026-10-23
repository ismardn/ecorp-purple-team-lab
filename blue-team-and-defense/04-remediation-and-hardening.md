# 04 - Plan de remédiation et durcissement (hardening)

L'analyse de la télémétrie et des vecteurs de compromission a mis en évidence une combinaison de vulnérabilités applicatives, de défauts d'architecture réseau et de lacunes dans le durcissement de l'Active Directory. 

Ce document propose un plan d'action priorisé pour sécuriser l'infrastructure d'E Corp et empêcher la reproduction d'une chaîne d'attaque (Kill Chain) similaire.

---

## 1. Bilan des vulnérabilités exploitées

La compromission totale du domaine E Corp n'est pas le fruit d'une unique faille, mais d'une combinaison critique de faiblesses, dont la plus grave se situe au niveau de la conception même du réseau.

### A. Sécurité périmétrique : l'aberration pfSense (le pivot central)

La faille la plus critique de cette infrastructure ne réside pas dans Log4Shell, mais dans la configuration du pare-feu pfSense. L'existence d'une règle de routage autorisant tout le trafic (`Pass Any to Any`) depuis le sous-réseau DMZ (`10.0.10.0/24`) vers le sous-réseau LAN (`10.0.20.0/24`) est une violation absolue du concept même de zone démilitarisée (Zero Trust).

C'est cette erreur qui a permis à l'attaquant, une fois le serveur web compromis, d'établir un tunnel SOCKS5 (Chisel) pour requêter le contrôleur de domaine et attaquer directement les postes internes via WinRM. Par définition, une machine en DMZ ne doit jamais pouvoir initier des connexions arbitraires vers le LAN.
Le pare-feu souffrait également d'une absence d'Egress Filtering (filtrage sortant), permettant au serveur web d'initier des connexions vers l'Internet public (ports 1389, 8000, 4444) pour rapatrier les charges utiles et établir le Reverse Shell.

**Action à réaliser (micro-segmentation) :**

1. **Default Deny :** Remplacer immédiatement la règle « Pass Any » par une règle de blocage total (`Deny Any`) de la DMZ vers le LAN ainsi que vers l'Internet public (WAN). Le serveur web ne doit pouvoir sortir que vers des destinations explicitement autorisées (ex: serveurs de mise à jour).
2. **Profilage via Elastic (Port-Basing) :** Utiliser la télémétrie réseau d'Elastic SIEM pour identifier la ligne de base (Baseline) des flux strictement nécessaires.
3. **Ouverture granulaire (Allow-listing) :** Autoriser uniquement l'IP du serveur web (`10.0.10.10`) à communiquer avec l'IP du DC (`10.0.20.5`) *exclusivement* sur le port LDAPS (636). Tous les autres ports internes (SMB, WinRM, RPC) doivent rester inaccessibles.

### B. Hébergement applicatif (AppSec)

- **Vulnérabilité publique (Log4Shell) :** Présence d'une version obsolète de la bibliothèque Log4j couplée à un environnement Java vieillissant, exposant l'application à une exécution de code à distance (CVE-2021-44228).
    * **Remédiation :** Mettre à jour l'environnement Java et la bibliothèque Log4j vers une version sécurisée (>= 2.17.1).
- **Absence d'isolation logicielle et trojanisation :** L'application n'était pas protégée en écriture contre son propre utilisateur de service. Le binaire `ecorp-portal.jar` appartenant à `ecorp-web`, l'attaquant a pu s'octroyer les droits d'écriture (`chmod u+w`), écraser l'application avec une version malveillante, puis exploiter la directive `Restart=on-failure` de Systemd en « tuant » le processus (`kill -9`) pour forcer le redémarrage sur le code trojanisé.
    * **Remédiation - Conteneurisation (Docker) :** Encapsuler l'application dans un conteneur exécuté par un utilisateur non-root. Coupler cette architecture avec un système de fichiers monté en lecture seule (`Read-Only Root Filesystem`). Toute compromission RCE restreindra l'attaquant à un environnement éphémère et isolé, bloquant la modification du binaire `.jar` et la manipulation des services de l'hôte.

### C. Active Directory et durcissement système (endpoint hardening)

- **Dette cryptographique (RC4-HMAC) :** Le Contrôleur de Domaine tolérait le chiffrement obsolète `etype 23`, rendant l'attaque de *Kerberoasting* techniquement exploitable sur les comptes à privilèges.
    * **Remédiation :** Configurer l'Active Directory via GPO pour rejeter le chiffrement RC4-HMAC et forcer l'usage exclusif d'AES-128 / AES-256 (`etype 17/18`).
- **Vulnérabilité du compte de service `svc_deploy` :** Utilisation d'un mot de passe trivial (`Password123!`).
    * **Remédiation :** Remplacer le compte par un gMSA (Group Managed Service Account) pour automatiser la rotation d'un mot de passe complexe de 120 caractères (neutralisant le Kerberoasting).
- **Hygiène des comptes (Tiering) et protection mémoire :** L'Administrateur du Domaine (`t.wellick`) possédait une session interactive sur un serveur standard (`MGMT01`). L'absence de protection de l'autorité de sécurité locale (`RunAsPPL` désactivé) a permis d'extraire la mémoire `lsass.dmp` contenant les condensats NTLM via un appel P/Invoke.
    * **Remédiation :** Imposer un modèle de Tiering interdisant la connexion de comptes Tier 0 sur des serveurs Tier 1/2. Activer la protection du processus LSA via GPO (`RunAsPPL=1`) pour bloquer l'accès à la mémoire de `lsass.exe`.

---

## 2. Ingénierie de détection (detection engineering) et couverture SIEM

L'analyse forensique détaillée dans le document `03-endpoint-and-ad-telemetry.md` a prouvé que l'infrastructure bénéficie déjà d'une stratégie de journalisation avancée et robuste (GPO d'audit strict, configuration Sysmon-Modular). Les événements les plus furtifs de l'attaque (compilation P/Invoke en mémoire, usage du GUID de réplication DCSync, rétrogradation Kerberos) sont parfaitement capturés à la source par les endpoints Windows.

Cependant, la matrice de couverture (`01-detection-coverage-matrix.md`) révèle que le SIEM est resté silencieux ou peu explicite sur ces actions. L'angle mort ne provient pas d'un manque de logs, mais des limites des règles de détection par défaut (Out-Of-The-Box) d'Elastic SIEM. Pour valoriser cette télémétrie, le SOC doit pivoter vers la création de règles personnalisées :

- **Corrélation réseau et système :** Il est impératif de croiser les couches pour désanonymiser les flux chiffrés. Le SIEM doit lier une alerte Suricata `WinRM User Agent Detected` (réseau) avec un événement système (Event ID 4688 / Sysmon 1) montrant la création d'un processus enfant de `wsmprovhost.exe` (système) dans une fenêtre temporelle réduite.
- **Détection comportementale avancée :** Délaisser les signatures statiques au profit de la logique comportementale. Le SIEM doit lever une alerte critique immédiate lorsqu'un événement `4662` (Directory Service Access) contient explicitement le GUID d'attaque DCSync (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`), ou lorsqu'un script PowerShell intercepté (Event `4104`) effectue un appel dynamique à l'API de dump mémoire `MiniDumpWriteDump`.

---

## 3. Stratégie de détection et réponse automatisée (active response)

Le temps de latence entre l'alerte SIEM et l'intervention humaine a permis à l'attaquant de finaliser sa Kill Chain. Une posture de défense proactive doit être adoptée.

### Déploiement de l'Active Response (Elastic et Suricata) :
L'objectif n'est plus seulement d'alerter, mais de briser la chaîne d'attaque instantanément lors de la détection de comportements à haute fidélité (True Positives).

1.  **Isolation d'hôte (endpoint isolation) :**
    *   Configurer l'Agent Elastic pour isoler automatiquement du réseau toute machine (DMZ ou LAN) levant une alerte de type « Reverse Shell Activity » ou « LSASS Memory Dump Creation ». La machine isolée ne conservera qu'un canal chiffré exclusif avec le SIEM pour l'investigation forensique.
2.  **Blocage périmétrique automatisé :**
    *   Mettre en place un webhook entre le SIEM et le pare-feu pfSense. Dès qu'une signature NIDS critique est levée par Suricata (ex: `ET EXPLOIT Apache log4j RCE Attempt`), l'adresse IP source attaquante (`192.168.1.150`) est automatiquement injectée dans une table de blocage (`pfB_Block_IP`) sur l'interface WAN du pare-feu pour une durée déterminée.