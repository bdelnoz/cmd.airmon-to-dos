<!--
Document : USAGE.md
Auteur : Bruno DELNOZ
Email : bruno.delnoz@protonmail.com
Version : v51.1.0
Date : 2026-04-20 11:38
-->
# Usage Guide for `cmd.airmon-dos.sh`

## Quick Start

```bash
./cmd.airmon-dos.sh --help
```

If no argument is provided, the script displays help.

## Primary Execution

```bash
./cmd.airmon-dos.sh --exec iface=<interface> [options]
```

## Mandatory / Core Options

- `--help` / `-h`  
  Display complete help and examples.
- `--exec` / `-exe`  
  Execute main workflow.
- `--prerequis` / `-pr`  
  Check required prerequisites.
- `--install` / `-i`  
  Install missing prerequisites.
- `--simulate` / `-s`  
  Enable dry-run mode (no sensitive real action).
- `--changelog` / `-ch`  
  Display script changelog.

## Additional Parameters

- `iface=INTERFACE`  
  Required for execution and CSV rescan modes.
- `scan_duration=SECS`  
  Scan duration in seconds. Default: `90`.
- `interval=SECS`  
  Interval between cycles. Default: `15`.
- `mode=loop|once`  
  Execution mode. Default: `loop`.
- `dos=real|simulation`  
  DOS action mode. Default: `real`.
- `max_cycles=N`  
  Max cycles in loop mode (`0` means infinite). Default: `0`.
- `deauth_count=N`  
  Number of deauth packets. Default: `10`.

## Special Modes

- `--rescan-csv`  
  Reprocess existing CSV files.
- `--rescan-csv-rename`  
  Reprocess CSV files and rename processed files.
- `--convert`  
  Convert `.md` docs to `.docx` and `.pdf` via `pandoc`.
- `delete`  
  Delete generated files with confirmation.

## Examples

```bash
# Infinite loop with real DOS mode
./cmd.airmon-dos.sh --exec iface=wlan1 mode=loop dos=real deauth_count=15

# Single scan in simulation mode
./cmd.airmon-dos.sh --exec iface=wlan1 mode=once scan_duration=120 dos=simulation

# Loop mode with bounded cycles
./cmd.airmon-dos.sh --exec iface=wlan1 mode=loop max_cycles=5 interval=20 deauth_count=5

# Prerequisite checks
./cmd.airmon-dos.sh --prerequis

# Install missing dependencies
./cmd.airmon-dos.sh --install

# Show changelog
./cmd.airmon-dos.sh --changelog
```

## Operational Notes

- Use only on authorized networks.
- `--simulate` can be combined with `--exec` to avoid real attack actions.
- Script uses dedicated folders for logs and results.
