<!--
Document : INSTALL.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.1.0
Date : 2026-04-20 11:38
-->
# Installation Instructions for `cmd.airmon-dos.sh`

## Purpose

This guide documents installation and prerequisite verification for the current repository script.

## Required Tools

The script expects these tools to be available:

- `aircrack-ng` (includes `airmon-ng`, `airodump-ng`, `aireplay-ng`)
- `nmap` (for MAC/OUI vendor lookup flows)
- `pandoc` (for Markdown conversion via `--convert`)
- standard CLI tools (`awk`, `grep`, `sed`, `cut`, `timeout`, etc.)

## Recommended Setup

1. Ensure your system packages are updated.
2. Make the script executable.
3. Run prerequisites check.
4. Install missing dependencies if needed.

## Commands

```bash
chmod +x ./cmd.airmon-dos.sh
./cmd.airmon-dos.sh --prerequis
./cmd.airmon-dos.sh --install
```

## Notes

- The script integrates installation workflow through `--install`.
- Depending on your system, elevated privileges may be required by underlying package manager commands.
- After installation, validate with:

```bash
./cmd.airmon-dos.sh --help
```
