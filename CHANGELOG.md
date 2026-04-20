<!--
Document : CHANGELOG.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.1.0
Date : 2026-04-20 11:38
-->
# Changelog for cmd.airmon-dos.fr.sh

## v51.1.0 (2026-04-20 11:38) : DOCUMENTATION SYNCHRONIZATION
- Synchronized `README.md`, `USAGE.md`, and `INSTALL.md` with current script options and runtime behavior.
- Added mandatory Markdown metadata headers to repository documentation files.
- Clarified operational commands and examples without modifying script logic or script features.

## v51 (2025-11-11) : ENHANCEMENTS AND ADAPTATIONS
- Translated all comments, messages, help, and outputs to English for consistency
- Added mandatory arguments: --help, --exec, --prerequis, --install, --simulate, --changelog
- Integrated automatic .gitignore management with checks and additions for /logs, /outputs, /results, /infos
- Added automatic creation and update of documentation files (README.md, CHANGELOG.md, USAGE.md, INSTALL.md) in ./infos
- Implemented prerequisites checking (--prerequis) for required tools (aircrack-ng, nmap, etc.)
- Added installation of missing prerequisites via --install (assuming Debian/Ubuntu with apt)
- Introduced progress status display for multi-step execution (e.g., Step 1/10: Enabling monitor mode)
- Added post-execution numbered list of all actions performed
- Modified logging to use ./logs with formatted filename: log.cmd.airmon-dos.fr.<TIMESTAMPFULL>.<VERSION>.log
- Moved output files (CSV, CAP, reports) to ./results directory
- Ensured code length increase with detailed internal comments for every block and section
- Added detailed explanations in code comments for logic
- Integrated --simulate for dry-run mode, overriding DOS to simulation when present
- Added --convert for optional conversion of .md docs to .docx and .pdf using pandoc
- Enhanced error handling and verbose logging for all new features
- Maintained all existing functions without removal or simplification

## v50 (2025-11-09) : CRITICAL FIXES
- FIX: Channel extraction in run_scan() for DOS attacks
- FIX: Passing channel to dos_attack_real() and dos_attack_simulation()
- Improved error messages and logging
- Improved documentation
- Added additional verifications

## v49 (2025-07-28) :
- Enriched help with detailed usage examples
- Complete options reminder in help

