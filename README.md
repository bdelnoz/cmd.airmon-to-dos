<!--
Document : README.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.1.0
Date : 2026-04-20 11:38
-->
# Documentation for `cmd.airmon-dos.sh`

Author: Bruno DELNOZ  
Email: bruno.delnoz@protonmail.com  
Script aligned version: v51  
Last documentation update: 2026-04-20 11:38 (UTC)

## Overview

`cmd.airmon-dos.sh` is a Wi-Fi auditing script built around the Aircrack-ng suite. It can:

- Check and install prerequisites.
- Run single or looped scan cycles.
- Detect APs and clients from capture CSV outputs.
- Launch deauthentication tests in **real** or **simulation** mode.
- Reprocess previously generated CSV files.
- Generate logs and reports in dedicated directories.
- Convert local Markdown documentation to DOCX/PDF via `pandoc`.

> This script is intended for testing and auditing on networks you own or are authorized to test.

## Key Capabilities

- Mandatory operational entrypoint: `--exec`.
- Safety mode: `--simulate` (dry-run behavior for sensitive actions).
- Dependency workflow:
  - `--prerequis` to verify required tools.
  - `--install` to install missing tools.
- Changelog display: `--changelog`.
- Documentation conversion: `--convert`.
- Cleanup command: `delete`.

## Runtime Inputs

Main argument family supported by the script:

- `iface=<name>`
- `scan_duration=<seconds>`
- `interval=<seconds>`
- `mode=loop|once`
- `dos=real|simulation`
- `max_cycles=<number>`
- `deauth_count=<number>`

## Generated Artifacts

By default, script outputs are organized into:

- `./logs` for execution logs.
- `./results` for reports and processed outputs.
- `./infos` for script-managed documentation artifacts.
- `./outputs` reserved for output extensions and compatibility.

## Related Documentation

- [`USAGE.md`](./USAGE.md) for full command syntax and examples.
- [`INSTALL.md`](./INSTALL.md) for prerequisites and setup path.
- [`CHANGELOG.md`](./CHANGELOG.md) for version history.

## Current Task Note

This repository documentation has been synchronized with currently available script options and behaviors **without changing script logic or script features**.
