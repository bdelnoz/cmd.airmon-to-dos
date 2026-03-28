<!--
Document : WHY.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.0.0
Date : 2026-03-28 00:27
-->
# WHY.md

## Pourquoi ce projet existe
Le projet `cmd.airmon-dos.sh` vise à fournir un outil Bash unique pour :
- observer rapidement un environnement Wi-Fi,
- documenter les résultats de scan,
- faciliter des scénarios d'audit contrôlé,
- maintenir une trace exploitable via logs et rapports.

## Objectifs opérationnels
1. Réduire le temps de préparation d'un audit technique Wi-Fi.
2. Standardiser les sorties (`./logs`, `./results`) et la traçabilité.
3. Permettre un mode simulation afin de valider le workflow sans action sensible.
4. Supporter le retraitement de captures CSV déjà générées.

## Contraintes prises en compte
- Exécution sur des environnements Linux orientés audit.
- Dépendance à des outils externes (`aircrack-ng`, `nmap`, etc.).
- Besoin de privilèges élevés pour certaines opérations.
- Nécessité de rester dans un cadre légal strict.

## Limites connues
- Le script dépend du matériel Wi-Fi, des drivers et de la stabilité monitor mode.
- Les actions réseau actives peuvent être bloquées ou interdites selon le contexte.
- L'installation automatique est orientée distributions compatibles `apt`.

## Positionnement
Ce dépôt est pensé comme un socle opérationnel reproductible, documenté et extensible,
à utiliser uniquement dans un contexte d'audit autorisé.
