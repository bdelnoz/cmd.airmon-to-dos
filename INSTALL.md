<!--
Document : INSTALL.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.0.0
Date : 2026-03-28 00:27
-->
# INSTALL.md

## Portée
Ce document décrit l'installation et la préparation de `cmd.airmon-dos.sh`.

## Pré-requis système
- `aircrack-ng` (inclut `airmon-ng`, `airodump-ng`, `aireplay-ng`)
- `nmap`
- `pandoc` (optionnel si conversion documentaire)
- Outils standards : `awk`, `grep`, `sed`, `ip`, `iwconfig`

## Installation automatisée
Depuis la racine du dépôt :

```bash
./cmd.airmon-dos.sh --install
```

## Vérification des prérequis

```bash
./cmd.airmon-dos.sh --prerequis
```

## Notes d'exécution
- Le script intègre l'usage de `sudo` pour les actions nécessitant des privilèges.
- Ne pas lancer sur un réseau non autorisé.
- Vérifier l'interface Wi-Fi avant exécution (`iface=wlan0`, `iface=wlan1`, etc.).
