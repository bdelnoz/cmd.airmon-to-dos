<!--
Document : README.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.0.0
Date : 2026-03-28 00:27
-->
# README.md

## Présentation
`cmd.airmon-dos.sh` est un script Bash orienté audit Wi-Fi qui permet de :
- scanner les points d'accès et clients,
- produire des rapports horodatés,
- exécuter des actions de type deauthentication en mode réel ou simulation,
- retraiter des CSV existants,
- gérer des exclusions MAC.

## Script principal
- Nom complet : `cmd.airmon-dos.sh`
- Auteur : Bruno DELNOZ
- Contact : bruno.delnoz@protonmail.com
- Version script référencée : `v51`
- Dernière génération de cette documentation : `2026-03-28 00:27` (UTC)

## Arborescence attendue
- `./cmd.airmon-dos.sh`
- `./README.md`
- `./CHANGELOG.md`
- `./INSTALL.md`
- `./USAGE.md`
- `./WHY.md`
- `./exclusions.txt`
- `./logs/` (créé/exploité à l'exécution)
- `./results/` (créé/exploité à l'exécution)

## Sécurité et usage responsable
Les fonctions actives (deauth/DOS) sont réservées aux environnements autorisés et maîtrisés.
Utiliser exclusivement sur vos propres infrastructures, avec autorisation explicite.

## Fichiers de documentation liés
- Voir `USAGE.md` pour les options et exemples de commande.
- Voir `INSTALL.md` pour les prérequis et l'installation.
- Voir `CHANGELOG.md` pour l'historique détaillé.
- Voir `WHY.md` pour les objectifs et choix de conception.
