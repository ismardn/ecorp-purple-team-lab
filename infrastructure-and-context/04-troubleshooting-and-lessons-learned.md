# 04 - Troubleshooting et leçons apprises

Ce document recense les défis techniques majeurs rencontrés lors de la conception, du déploiement et de l'exploitation du lab E Corp. Construire une infrastructure Purple Team réaliste de bout en bout nécessite de nombreuses itérations. Cette section met en lumière les capacités de diagnostic, d'ingénierie système et d'évasion face aux mécanismes de sécurité modernes.

---

## 1. Infrastructure réseau et data pipeline (build)

### 1.1 Le mur de l'UDP et le parsing Suricata (problème majeur)
-   **Problème :** Le SIEM recevait correctement les alertes de sécurité basiques au format texte brut (`fast.log`) générées par Suricata sur pfSense, mais la transmission des journaux enrichis (`eve.json`) échouait.
-   **Analyse :** Deux causes ont été identifiées. Premièrement, pfSense envoyait initialement les logs via le protocole UDP (format `fast.log`), qui tronquait les paquets dépassant le MTU (1500 octets), perdant ainsi la signature des attaques complexes. Deuxièmement, le SIEM a besoin du format JSON riche (`eve.json`) pour parser les métadonnées de l'attaque. 
-   **Analyse :** La cause racine réside dans la limite physique du protocole UDP face à la taille des journaux de sécurité. Si l'UDP parvenait à transmettre les alertes basiques au format texte court (`fast.log`), il échouait silencieusement lors de l'envoi du format riche `eve.json`. En effet, dès qu'une attaque complexe générait un journal contenant le payload complet, la taille de la structure JSON dépassait le MTU réseau (1500 octets), entraînant la troncation et la perte du paquet.
-   **Solution :** Utilisation du service `Syslog-ng` à installer sur pfSense. Configuration d'un flux TCP pur lisant directement le fichier `/var/log/suricata/.../eve.json` avec l'indicateur `no-parse`, envoyé avec le template strict `${MSG}\n`. Cette méthode garantit l'intégrité des paquets volumineux.

### 1.2 Limites de Wazuh et migration vers Elastic Security
-   **Problème :** Initialement déployé comme solution SIEM/XDR, Wazuh s'est avéré inadapté pour détecter les mouvements latéraux complexes et les attaques Active Directory avancées. Cela aurait nécessité un nombre de règles personnalisées beaucoup trop important pour corréler ces événements.
-   **Solution :** Refonte complète du pipeline de monitoring et migration vers la stack **Elastic Security (ELK)** avec Elastic Agent / Fleet.
-   **Leçon :** Elastic propose plus de 1900 règles natives pré-mappées sur le framework MITRE ATT&CK et des langages d'interrogation puissants (KQL, EQL) spécifiquement taillés pour le Threat Hunting. Ce choix technique est également plus aligné avec les standards "mainstream" des SOC modernes (Security Operations Centers), offrant une meilleure montée en compétences, en plus d'une meilleure détection des attaques Active Directory.

---

## 2. Ingénierie du scénario et exécution (Red Team)

### 2.1 Conception de la kill chain : le défi du réalisme
-   **Problème :** Construire une chaîne de compromission complète (kill chain) qui soit à la fois exploitable, intéressante à documenter et techniquement réaliste pour une entreprise à l'heure actuelle n'est pas trivial. De nombreuses attaques classiques CTF (Capture The Flag) s'avèrent impossibles ou absurdes dans un réseau d'entreprise segmenté.
-   **Solution et leçon :** Le scénario a nécessité de multiples refontes (notamment l'abandon d'une évasion Docker initiale jugée moins réaliste en production) pour s'orienter vers un déploiement de l'application vulnérable géré via un service `systemd` restreint. Le choix du compte `svc_deploy` avec des droits d'administrateur local a également été minutieusement pensé pour justifier la présence d'un SPN exploitable tout en restant cohérent avec les pratiques de déploiement de logiciels en entreprise.

### 2.2 Log4Shell et la restriction trustURLCodebase
-   **Problème :** Dans une volonté initiale de réalisme, le serveur web vulnérable a été provisionné avec une version relativement récente de Java. Lors de l'exploitation de la CVE-2021-44228, le payload JNDI déclenchait bien la connexion LDAP, mais le téléchargement et l'exécution de la classe Java distante (`Exploit.class`) échouaient systématiquement.
-   **Analyse :** Depuis les versions récentes de Java, le paramètre `com.sun.jndi.ldap.object.trustURLCodebase` est défini sur `false` par défaut, ce qui bloque le chargement de code distant, rendant l'exécution de code à distance (RCE) directe inopérante.
-   **Solution :** Pour conserver la viabilité de la faille Log4j, la version de Java a été intentionnellement rétrogradée vers la version `JDK 1.8.0_181`. Ce choix a été justifié scénaristiquement par le maintien d'une application "legacy" (serveur oublié) que l'équipe infrastructure craint de mettre à jour.

### 2.3 Évasion d'antivirus : le dump LSASS bloqué par Defender
-   **Problème :** Lors de la phase de mouvement latéral, l'objectif était d'extraire les hachages NTLM en mémoire via un dump du processus LSASS. L'utilisation d'outils standards (`procdump.exe`, `mimikatz.exe`) ou de scripts PowerShell connus (comme `Out-Minidump.ps1`) entraînait la suppression immédiate des fichiers par Windows Defender et la levée d'alertes critiques.
-   **Solution :** L'approche a été modifiée pour utiliser une technique avancée via un script PowerShell nommé `lsaKiller.ps1` (trouvé sur le dépôt GitHub `florylsk/active-directory-hacktools`). 
-   **Leçon :** Ce script contourne les signatures statiques de Defender en utilisant la cmdlet `Add-Type` pour compiler du code C# à la volée. Cela permet d'invoquer directement la fonction `MiniDumpWriteDump` de la bibliothèque native `dbghelp.dll` (via P/Invoke), mimant le comportement d'un processus de débogage légitime du système d'exploitation.

---

## 3. Détection et télémétrie (Blue Team)

### 3.1 La cécité du SIEM : le piège Sysmon (SwiftOnSecurity vs Olaf Hartong)
-   **Problème :** Malgré un SIEM opérationnel et le déploiement de l'agent Elastic, certaines attaques critiques (comme le dump LSASS en mémoire) ne déclenchaient aucune alerte dans le tableau de bord, bien que les logs réseau remontent.
-   **Analyse :** La configuration Sysmon utilisée sur les hôtes Windows était celle de *SwiftOnSecurity*. Conçue pour de la bureautique en production, elle filtre agressivement les événements pour économiser l'espace disque. Les logs d'attaque n'étaient donc tout simplement pas générés par le système d'exploitation.
-   **Solution :** Remplacement à chaud par la configuration **Sysmon-Modular d'Olaf Hartong**, conçue spécifiquement pour la détection des techniques offensives (Threat Hunting). Couplée à l'activation par GPO du *Script Block Logging* de PowerShell (Event 4104), le SIEM a instantanément recouvré la vue sur les attaques en mémoire et les *Living off the Land Binaries* (LOLBins).
-   **Leçon :** Un moteur de corrélation très puissant (Elastic) est totalement inutile si la politique d'audit du point de terminaison (Sysmon, GPO) étouffe le signal à la source.