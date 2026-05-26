# WPA3 Attack Guide

This guide covers WPA3-SAE attack strategies, usage examples, and tool requirements for wifite2.  
For issue-specific troubleshooting see [WPA3 Troubleshooting](WPA3_TROUBLESHOOTING.md).

## Table of Contents

1. [Overview](#overview)
2. [Network Types](#network-types)
3. [Attack Strategies](#attack-strategies)
4. [Basic Usage](#basic-usage)
5. [Advanced Options](#advanced-options)
6. [Tool Requirements](#tool-requirements)
7. [Related Docs](#related-docs)

---

## Overview

Wifite2 supports WPA3-SAE attacks with automatic network detection and intelligent strategy selection.
It handles transition-mode downgrade, SAE handshake capture, PMF detection, and Dragonblood scanning.

---

## Network Types

| Type | Description |
|------|-------------|
| **WPA3-only** | Pure WPA3 — requires SAE handshake capture |
| **WPA3-Transition** | Mixed WPA2/WPA3 — downgrade attack possible |
| **PMF Required** | Protected Management Frames enabled — no deauth possible; passive capture only |
| **PMF Optional** | PMF supported but not required — deauth works |

Wifite automatically detects these configurations and selects the optimal strategy.

---

## Attack Strategies

Wifite automatically selects the best strategy based on the target network:

### 1. Transition Mode Downgrade (highest success rate)

- Detects WPA2/WPA3 mixed networks automatically
- Forces clients to authenticate with WPA2 instead of WPA3
- Captures a standard WPA2 handshake for offline cracking
- Fastest and most reliable method on transition-mode networks

### 2. SAE Handshake Capture

- Captures the WPA3-SAE authentication exchange
- Converts to hashcat format (mode 22000) for offline cracking
- Works on pure WPA3 networks
- Requires GPU acceleration for efficient cracking

### 3. Passive Capture (PMF Required)

- Used when PMF prevents deauthentication
- Waits for natural client reconnections
- No active interference with the network
- Slower but works on PMF-protected networks

### 4. Dragonblood Detection (CVE-2019-13377)

- Identifies networks vulnerable to known WPA3 implementation flaws
- Reports weak SAE groups and timing-attack susceptibility
- Informational only — not all detected vulnerabilities are exploitable

---

## Basic Usage

```bash
# Attack all networks including WPA3 (automatic detection)
sudo wifite

# Show only WPA3 networks in scan
sudo wifite --wpa3

# Target only WPA3-SAE networks (skip WPA2-only targets)
sudo wifite --wpa3-only

# Force SAE capture — skip downgrade attempt on transition-mode networks
sudo wifite --force-sae

# Disable downgrade attacks — capture SAE directly
sudo wifite --no-downgrade

# Scan for Dragonblood vulnerabilities only (no attack)
sudo wifite --check-dragonblood
```

---

## Advanced Options

| Flag | Description |
|------|-------------|
| `--wpa3-only` | Attack only WPA3-SAE targets |
| `--force-sae` | Skip WPA2 on transition-mode; capture SAE directly |
| `--no-downgrade` | Disable transition-mode downgrade; pure SAE only |
| `--check-dragonblood` | Scan for Dragonblood vulnerabilities, no attack |
| `--wpa3-timeout [sec]` | Timeout for SAE capture / downgrade attempts |
| `--dragonblood-timing` | Enable Dragonblood timing attack (CVE-2019-13377) |
| `--dragonblood-samples [n]` | Timing samples per password candidate (default: 3) |
| `--dragonblood-max [n]` | Max passwords to probe in Dragonblood attack (default: 50) |
| `--no-deauths` | Passive mode — never deauthenticate clients |

```bash
# Attack a specific WPA3 network by BSSID
sudo wifite -b AA:BB:CC:DD:EE:FF

# Extended timeout (useful for PMF passive capture)
sudo wifite --wpa3-timeout 600

# Crack a captured WPA3 handshake with a wordlist
sudo wifite --crack --dict /path/to/wordlist.txt

# Verbose mode to trace WPA3 detection and strategy selection
sudo wifite -vv
```

---

## Tool Requirements

WPA3 attacks require these tools at the minimum versions listed:

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool) | 6.0.0 | SAE frame capture |
| [`hcxpcapngtool`](https://github.com/ZerBea/hcxtools) | 6.0.0 | Convert captures to hashcat format |
| [`hashcat`](https://hashcat.net/) | 6.0.0 | Mode 22000 cracking |
| [`tshark`](https://www.wireshark.org/) | 3.0.0 | Optional: frame analysis |

### Install on Kali Linux / Debian

```bash
sudo apt update
sudo apt install hcxdumptool hcxtools hashcat
```

### Install on Arch Linux

```bash
sudo pacman -S hcxtools hcxdumptool hashcat wireshark-cli
```

### Verify

```bash
hcxdumptool --version   # Should be 6.0.0+
hcxpcapngtool --version # Should be 6.0.0+
hashcat --version        # Should be 6.0.0+
hashcat --help | grep 22000  # Should show "WPA-PBKDF2-PMKID+EAPOL"
```

---

## Related Docs

- [WPA3 Troubleshooting](WPA3_TROUBLESHOOTING.md) — PMF handling, capture issues, hashcat errors
- [WPA3 Detection Optimization](WPA3_DETECTION_OPTIMIZATION.md) — Improving WPA3 detection accuracy
