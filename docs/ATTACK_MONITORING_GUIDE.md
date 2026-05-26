# Wireless Attack Monitoring Guide

Wifite2 includes a passive wireless attack monitoring mode that detects and logs malicious
802.11 management frames (deauthentication and disassociation attacks) in real time.

## Table of Contents

1. [Overview](#overview)
2. [Basic Usage](#basic-usage)
3. [All Options](#all-options)
4. [TUI Display](#tui-display)
5. [Log File Format](#log-file-format)
6. [Advanced Examples](#advanced-examples)
7. [Performance Notes](#performance-notes)
8. [FAQ](#faq)

---

## Overview

The attack monitor passively captures and analyzes:

- **Deauthentication frames** — used to forcibly disconnect clients from APs
- **Disassociation frames** — used to terminate client associations
- **Attack patterns** — identifies which networks are under attack and which devices are attacking
- **Network statistics** — most-attacked networks and most-active attacker MACs

**Requirements:** `tshark` (install with `sudo apt install tshark` on Debian/Ubuntu or
`sudo pacman -S wireshark-cli` on Arch).  Monitor mode is enabled automatically.

> **Note:** Attack monitoring is a standalone mode — it cannot run simultaneously with other
> wifite attack modes such as `--wpa` or `--eviltwin`.

---

## Basic Usage

```bash
# Start attack monitoring (infinite duration)
sudo wifite --monitor-attacks

# Monitor for a specific duration (seconds)
sudo wifite --monitor-attacks --monitor-duration 300

# Monitor a specific channel
sudo wifite --monitor-attacks --monitor-channel 6

# Enable channel hopping (all 2.4 GHz channels)
sudo wifite --monitor-attacks --monitor-hop

# Write events to a log file
sudo wifite --monitor-attacks --monitor-log /path/to/attacks.log

# Classic text mode (no TUI)
sudo wifite --monitor-attacks --no-tui
```

---

## All Options

| Flag | Description |
|------|-------------|
| `--monitor-attacks` | Start wireless attack monitoring mode |
| `--monitor-duration [sec]` | Run for this many seconds (0 = infinite, default) |
| `--monitor-channel [ch]` | Focus on a single channel (e.g. `--monitor-channel 6`) |
| `--monitor-hop` | Cycle through all 2.4 GHz channels (cannot combine with `--monitor-channel`) |
| `--monitor-log [file]` | Path for log file (default: `attack_monitor_<timestamp>.log`) |
| `--no-tui` | Use classic text mode instead of the TUI dashboard |

---

## TUI Display

When running in TUI mode (default) the dashboard has four panels:

### 1. Attack Statistics

- Total deauthentication frames detected
- Total disassociation frames detected
- Unique networks under attack
- Unique attacker MAC addresses
- Monitoring duration

### 2. Recent Attack Events

- Scrollable list of the last 100 events
- Color-coded: red = deauth, orange = disassoc
- Shows timestamp, attack type, target network, and attacker MAC
- Auto-scrolls to newest events

### 3. Networks Under Attack

- Top 20 most-attacked networks
- Shows ESSID, BSSID, attack count, and last-seen time
- Sorted by attack count (most attacked first)

### 4. Active Attackers

- Top 10 most active attacker MACs
- Shows MAC address, attack count, and number of unique targets
- Sorted by attack count

---

## Log File Format

Each event is logged as a pipe-delimited line:

```
2025-10-30T15:23:45.123456 | DEAUTH | Attacker: AA:BB:CC:DD:EE:FF | Target: 11:22:33:44:55:66 | BSSID: AA:BB:CC:DD:EE:FF | ESSID: MyNetwork | Channel: 6
```

Fields: ISO 8601 timestamp | attack type (DEAUTH / DISASSOC) | source MAC | destination MAC | BSSID | ESSID | channel.  
The structured format is easy to parse with `awk`, `grep`, Python, or import into spreadsheets / databases.

---

## Advanced Examples

**Security assessment — 1-hour network audit:**
```bash
sudo wifite --monitor-attacks --monitor-duration 3600 --monitor-log security_audit.log
```

**Penetration testing — specific channel:**
```bash
sudo wifite -i wlan1 --monitor-attacks --monitor-channel 6 --monitor-duration 1800 --monitor-log pentest.log
```

**Area-wide surveillance — all 2.4 GHz channels:**
```bash
sudo wifite --monitor-attacks --monitor-hop --monitor-log research_data.log
```

**Long-term monitoring with timestamped logs:**
```bash
sudo wifite --monitor-attacks --monitor-hop --monitor-log "attacks_$(date +%Y%m%d_%H%M%S).log"
```

**Classic mode for resource-constrained systems:**
```bash
sudo wifite --monitor-attacks --monitor-channel 1 --no-tui --monitor-log attacks.log
```

---

## Performance Notes

- **CPU:** Minimal — tshark with BPF filters is efficient.
- **Memory:** Low — event list is capped at 100 entries.
- **Disk:** Depends on attack frequency; logs are buffered and flushed periodically.

Tips:
- Use `--monitor-channel` to focus on one channel and reduce CPU load.
- Use `--no-tui` on resource-constrained or headless systems.
- Rotate log files to prevent excessive disk growth on long-running sessions.
- Can handle 1,000+ frames/second efficiently.

---

## FAQ

**Q: Can I monitor attacks while running other wifite attacks?**  
A: No. Attack monitoring is a standalone mode.

**Q: Will this interfere with networks?**  
A: No. Monitoring is completely passive — no packets are transmitted.

**Q: How accurate is detection?**  
A: Very accurate for genuine deauth/disassoc frames based on 802.11 frame types.
Note that some legitimate operations (AP reboot, client roaming) also use these frames.

**Q: Can I monitor 5 GHz networks?**  
A: Yes, if your adapter supports 5 GHz monitor mode. Use `--monitor-channel` with a 5 GHz channel number (e.g. 36, 40, 44, 48).

**Q: `--monitor-channel` vs `--monitor-hop`?**  
A: `--monitor-channel` captures everything on one channel with no missed frames.
`--monitor-hop` cycles all 2.4 GHz channels for area-wide detection but may miss some frames.

**Q: I detect attacks on my network — what should I do?**  
A: Verify the attacks are unauthorized. If confirmed malicious: document the evidence,
locate the attacker by MAC/signal if possible, implement countermeasures (WPA3, PMF),
and report to appropriate authorities if needed.

**Q: Can attackers detect that I'm monitoring?**  
A: No. Passive monitoring is undetectable — your adapter only receives frames.
