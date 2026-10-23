# Red Team : émulation d'adversaire (Kill Chain)

> **Avertissement :** Les techniques, scripts et méthodologies documentés dans cette section ont été exécutés dans un environnement de laboratoire strictement isolé et contrôlé. Ils sont présentés ici dans un but formatif : découvrir le fonctionnement d'une chaîne d'attaque complète, comprendre comment des vulnérabilités individuelles peuvent être combinées pour aboutir à une compromission totale du système d'information, et étudier en parallèle les mécanismes de défense et de détection correspondants.

Cette section détaille l'exécution d'une simulation d'attaque de type APT (Advanced Persistent Threat) ciblant l'infrastructure de la société fictive E Corp. 

L'objectif de cette campagne offensive est d'évaluer la résilience de l'architecture réseau et la capacité de détection du SIEM. L'attaque suit un cheminement réaliste et progressif : depuis l'exploitation d'une vulnérabilité publique sur un serveur exposé en DMZ, jusqu'à la compromission totale de l'Active Directory (Domain Takeover) et le déploiement simulé d'un ransomware via les stratégies de groupe.

---

## Arsenal offensif (stack technique)

Afin de simuler un adversaire avancé, l'attaque combine des outils publics de post-exploitation et des techniques de contournement sur mesure (Living off the Land) :

-   **Accès initial et C2 :** Burp Suite, marshalsec, Netcat, Chisel, Proxychains.
-   **Reconnaissance et pivoting :** Scripts Bash/Python natifs, NetExec, BloodHound.
-   **Manipulation d'identifiants :** Impacket (GetUserSPNs, secretsdump, ticketer), Hashcat, pypykatz.
-   **Évasion et exécution :** Script C# via P/Invoke (PowerShell), tâche Cron, trojanisation de binaire Java.

---

## Table des matières (phases de l'attaque)

La documentation est structurée chronologiquement selon le framework MITRE ATT&CK. Cliquez sur les liens ci-dessous pour accéder à l'analyse technique détaillée de chaque phase :

| Phase | Fichier d'analyse | Description de l'objectif | TTPs majeures |
| :---: | :--- | :--- | :--- |
| **01** | [Accès initial et persistance](./01-initial-access-log4shell.md) | Exploitation de Log4Shell sur le portail RH externe et établissement du premier accès C2. | `T1190`, `T1053.003` |
| **02** | [Reconnaissance et trojanisation](./02-internal-recon-and-trojan.md) | Ingénierie inverse de l'application métier et injection d'un hook de credential harvesting. | `T1016`, `T1505` |
| **03** | [Énumération AD et kerberoasting](./03-ad-enum-and-kerberoasting.md) | Déploiement du proxy SOCKS, cartographie du domaine et cassage de ticket de service (TGS). | `T1090.001`, `T1558.003` |
| **04** | [Mouvement latéral et dump LSASS](./04-lateral-movement-and-lsass.md) | Vol de session d'un administrateur via une injection mémoire fileless (API MiniDumpWriteDump). | `T1018`, `T1003.001` |
| **05** | [Compromission totale et impact](./05-domain-takeover-and-impact.md) | Extraction du hash `krbtgt`, forge du Golden Ticket et simulation d'un ransomware par GPO. | `T1558.001`, `T1484.001` |