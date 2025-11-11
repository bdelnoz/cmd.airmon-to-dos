Usage: ./cmd.airmon-dos.sh --exec [options]
Mandatory Options:
  --help (-h)         : Display this complete help with examples (default if no arguments)
  --exec (-exe)       : Execute the main script functionality
  --prerequis (-pr)   : Check prerequisites before execution (tools like aircrack-ng, nmap)
  --install (-i)      : Install missing prerequisites (requires sudo)
  --simulate (-s)     : Enable dry-run mode (simulation for sensitive actions like DOS attacks)
  --changelog (-ch)   : Display the complete changelog of the script

Additional Options:
  iface=INTERFACE     : WiFi interface (required for exec/rescan, possible values: wlan0, wlan1, etc.)
  scan_duration=SECS  : Scan duration in seconds (default: 90, positive integer)
  interval=SECS       : Interval between cycles in seconds (default: 15, positive integer)
  mode=loop|once      : Execution mode (default: loop, possible: loop, once)
  dos=real|simulation : DOS detection type (default: real, possible: real, simulation) - overridden by --simulate
  max_cycles=N        : Maximum number of cycles (0 = infinite, default: 0, non-negative integer)
  deauth_count=N      : Number of deauthentication packets (default: 10, positive integer)

Special Modes:
  --rescan-csv        : Reprocess existing CSV files (requires iface)
  --rescan-csv-rename : Reprocess CSV with renaming to .done after processing (requires iface)
  --convert           : Convert documentation .md files to .docx and .pdf using pandoc
  delete              : Cleanly delete generated files after confirmation

Examples of usage:
1) Run infinite loop scan on wlan1 with real DOS detection (15 packets):
   ./cmd.airmon-dos.sh --exec iface=wlan1 mode=loop dos=real deauth_count=15
2) Perform a single 120-second scan in simulation mode on wlan1:
   ./cmd.airmon-dos.sh --exec iface=wlan1 mode=once scan_duration=120 dos=simulation
3) Run loop scan (max 5 cycles, 20s interval, 5 packets):
   ./cmd.airmon-dos.sh --exec iface=wlan1 mode=loop max_cycles=5 interval=20 deauth_count=5
4) Reprocess existing CSV files with simulated DOS attack:
   ./cmd.airmon-dos.sh --rescan-csv iface=wlan1 dos=simulation
5) Reprocess CSV with renaming of processed files (.done suffix):
   ./cmd.airmon-dos.sh --rescan-csv-rename iface=wlan1
6) Check prerequisites only:
   ./cmd.airmon-dos.sh --prerequis
7) Install missing prerequisites:
   ./cmd.airmon-dos.sh --install
8) Run in simulation mode with exec:
   ./cmd.airmon-dos.sh --exec --simulate iface=wlan1
9) Display changelog:
   ./cmd.airmon-dos.sh --changelog
10) Convert documentation files:
   ./cmd.airmon-dos.sh --convert
11) Delete all generated files:
   ./cmd.airmon-dos.sh delete

Important notes:
- Adjust "scan_duration" and "interval" based on estimated DOS attack duration, especially with high "deauth_count".
- The script automatically adjusts pauses between cycles based on real time spent on attacks.
- Run with necessary privileges (sudo embedded where possible).
- DOS attacks are for testing/auditing on YOUR own networks only.
- Logs in ./logs, results in ./results, docs in ./infos.
- If --simulate is used, no real modifications or attacks occur.
