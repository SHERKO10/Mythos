# Explication Technique : Framework Mythos C2

Ce document sert de référence technique pour expliquer l'architecture, les composants et le fonctionnement global du projet Mythos C2 à un autre expert technique, développeur ou spécialiste en cybersécurité.

---

## 1. Vue d'ensemble du Projet

**Mythos C2** est un framework de **Command & Control (C2)** orienté **Red Team**. 
Son objectif principal est de maintenir un accès persistant sur une machine compromise et de lui envoyer des commandes à distance de manière furtive et sécurisée. 

L'architecture repose sur un modèle asynchrone Client-Serveur séparé en deux langages distincts pour tirer parti de leurs avantages respectifs :
*   **Le Team Server (Backend)** : Développé en **Go** pour ses hautes performances, sa gestion native de la concurrence (goroutines) et sa facilité de déploiement (binaire statique).
*   **L'Agent / Implant (Client)** : Développé en **Rust** pour garantir une exécution bas niveau sécurisée (gestion de la mémoire), une grande rapidité, et une forte résistance à la rétro-ingénierie (analyse statique par les Blue Teams).

---

## 2. Le Team Server (Go) - `server/main.go`

Le backend en Go est le centre de contrôle. Il est asynchrone et gère deux flux de communication distincts de manière simultanée :

1.  **Le Listener HTTPS (Interface Agent) :**
    C'est le point d'entrée pour les agents infectés déployés sur les cibles. Il écoute en continu les connexions entrantes (les "beacons").
2.  **L'API REST (Interface Opérateur) :**
    C'est le point d'entrée pour les attaquants (opérateurs Red Team). Sécurisée par des tokens **JWT** (JSON Web Tokens), cette API permet aux opérateurs de s'authentifier, de lister les machines compromises, et d'injecter de nouvelles commandes dans la file d'attente d'un agent.
3.  **La Console Opérateur (`server/operator/console.go`) :**
    Un client CLI dédié en Go qui consomme l'API REST. Il permet aux opérateurs de piloter les agents via des commandes (comme `shell`, `powershell`, `sleep`). C'est l'interface principale d'utilisation du C2.

**Gestion de l'état :**
Le serveur utilise une base de données embarquée **SQLite** pour persister les données (état des agents, historique des tâches, résultats des commandes). 
Un **Watchdog** (une routine d'arrière-plan) s'exécute toutes les 5 minutes pour balayer la base de données et marquer comme "morts" (dead) les agents qui n'ont pas donné signe de vie depuis un certain temps.

---

## 3. L'Agent (Rust) - `agent/src/main.rs`

L'agent est le malware déployé sur la machine cible. Son développement a été pensé autour de l'**OPSEC** (sécurité opérationnelle et furtivité). Son cycle d'exécution se divise en 4 phases :

1.  **L'Évasion (Anti-sandbox & Anti-debug) :**
    Au tout premier lancement, la fonction `check_environment()` vérifie si le programme s'exécute dans un environnement d'analyse (sandbox d'antivirus, débogueur, etc.). Si une anomalie est détectée, le programme s'arrête instantanément et silencieusement (`exit(0)`) pour ne générer aucune alerte.
2.  **La Reconnaissance (Fingerprinting) :**
    L'agent effectue une collecte d'informations locales : nom d'hôte, utilisateur, niveau d'intégrité (privilèges administrateur ou non), architecture et OS.
3.  **L'Enregistrement (Handshake) :**
    L'agent contacte le Team Server pour s'enregistrer. C'est à ce moment que se fait l'échange de clés cryptographiques.
4.  **La Beacon Loop (Boucle principale) :**
    C'est le cœur du malware. L'agent entre dans une boucle infinie asynchrone :
    *   Il "dort" pendant une durée définie.
    *   Le temps de sommeil est altéré par un **"Jitter"** (une variation de temps aléatoire en pourcentage). Cela rend les requêtes réseau irrégulières, empêchant les pare-feux et les SOC de détecter un motif temporel répétitif (beaconing).
    *   Au réveil, il fait un "check-in" vers le serveur pour récupérer d'éventuelles tâches.
    *   S'il y a une tâche (ex: un shell de commande), il l'exécute et renvoie le résultat chiffré au serveur.
    *   **Gestion d'état persistant (Mode Pseudo-Interactif) :** Par défaut, les commandes asynchrones ne gardent pas de contexte (chaque commande ouvre un nouveau processus). L'agent intègre des modules natifs (comme `cd` et `pwd`) qui interagissent directement avec l'environnement du processus (`std::env::set_current_dir`) afin de simuler l'état d'un véritable shell continu pour l'opérateur.

---

## 4. Cryptographie et Sécurité des Communications

L'un des points forts du framework est sa résistance à l'inspection réseau (Network Traffic Analysis). Un double niveau de chiffrement est appliqué :

*   **Échange de clés asymétrique (ECDH) :**
    Lors du premier contact, l'agent et le serveur utilisent l'algorithme *Elliptic-Curve Diffie-Hellman* (ECDH). Cela leur permet de s'accorder sur un secret cryptographique partagé commun sur un canal public, sans jamais faire transiter ce secret sur le réseau.
*   **Chiffrement symétrique des Payloads (AES-256-GCM) :**
    Une fois le secret établi, toutes les données transigeant dans le corps (body) des requêtes HTTP (tâches, résultats, métriques) sont chiffrées de bout en bout avec l'algorithme AES-256 en mode GCM (qui garantit à la fois la confidentialité et l'authenticité des données). 
    *Conséquence : Même si une entreprise pratique l'inspection TLS (MITM) sur son réseau pour lire le trafic HTTPS, elle ne verra qu'un bloc de données illisible.*

---

## 5. Optimisations de Compilation (Rust)

Pour rendre le travail des équipes de défense (Blue Team / Reverse Engineers) extrêmement difficile, le fichier `Cargo.toml` de l'agent applique des optimisations de compilation drastiques :

*   `opt-level = 3` : Optimisation maximale pour la vitesse et la taille.
*   `strip = true` : Suppression totale des symboles de débogage (noms de fonctions, de variables).
*   `lto = true` (Link-Time Optimization) : Réduction drastique du poids du binaire.
*   `panic = "abort"` : Désactivation du déroulement de la pile (stack unwinding) en cas d'erreur fatale, rendant le binaire encore plus petit et masquant le flux d'exécution en cas de plantage provoqué par un analyste.

---

## 6. Le Mode "Pseudo-Interactif" (Furtivité vs. Rapidité)

Une des problématiques principales d'un C2 asynchrone est le manque de fluidité pour l'opérateur (nécessité de taper des commandes d'interrogation comme `tasks` en attendant la fin d'un *sleep*). 
Pour y remédier sans sacrifier la discrétion réseau, le framework intègre une commande `interactive`.

Lorsqu'activée, la console :
1. Envoie une commande `sleep 1` à l'agent pour réduire son cycle de "beaconing" (rendant les requêtes presque en temps réel).
2. Ouvre un *prompt* en apparence persistant (`mythos-shell >`). L'opérateur peut y taper des commandes naturelles (`whoami`, `dir`, `cd`).
3. Interroge automatiquement l'API en tâche de fond (polling) pour afficher la réponse de l'agent dès sa réception, masquant ainsi totalement le fonctionnement asynchrone sous-jacent.
4. Au moment de quitter (`exit`), la console restaure le `sleep` long par défaut, replongeant l'agent dans un état furtif et silencieux.

*Document mis à jour avec le mode interactif.*
