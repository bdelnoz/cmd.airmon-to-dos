<!--
Document : USAGE.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.0.0
Date : 2026-03-28 00:27
-->
# USAGE.md

## Commande générale

```bash
./cmd.airmon-dos.sh --exec [options]
```

## Options principales
- `--help` / `-h` : affiche l'aide complète.
- `--exec` / `-exe` : exécute le flux principal.
- `--prerequis` / `-pr` : vérifie les dépendances.
- `--install` / `-i` : installe les dépendances manquantes.
- `--simulate` / `-s` : active le mode dry-run.
- `--changelog` / `-ch` : affiche l'historique.
- `--rescan-csv` : retraitement CSV.
- `--rescan-csv-rename` : retraitement CSV + renommage `.done`.
- `--convert` : conversion `.md` vers `.docx` et `.pdf`.
- `delete` : suppression guidée des artefacts générés.

## Options additionnelles
- `iface=INTERFACE`
- `scan_duration=SECS` (défaut: `90`)
- `interval=SECS` (défaut: `15`)
- `mode=loop|once` (défaut: `loop`)
- `dos=real|simulation` (défaut: `real`)
- `max_cycles=N` (défaut: `0`, infini)
- `deauth_count=N` (défaut: `10`)

## Exemples

```bash
./cmd.airmon-dos.sh --exec iface=wlan1 mode=loop dos=simulation
./cmd.airmon-dos.sh --exec --simulate iface=wlan1 mode=once scan_duration=120
./cmd.airmon-dos.sh --rescan-csv iface=wlan1 dos=simulation
./cmd.airmon-dos.sh --prerequis
./cmd.airmon-dos.sh --changelog
```

## Avertissement
Les modes actifs réseau doivent rester strictement limités à un cadre légal et autorisé.
