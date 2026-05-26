# WPA-SEC Integration Guide

Wifite2 integrates with [wpa-sec.stanev.org](https://wpa-sec.stanev.org), a free online
WPA/WPA2/WPA3 password cracking service.  Upload captured handshakes and PMKIDs to leverage
distributed computing resources for offline cracking.

## Table of Contents

1. [Overview](#overview)
2. [Getting Your API Key](#getting-your-api-key)
3. [Quick Start](#quick-start)
4. [All Options](#all-options)
5. [Upload Modes](#upload-modes)
6. [Supported Capture Types](#supported-capture-types)
7. [Examples](#examples)
8. [Tool Requirements](#tool-requirements)
9. [Checking Results](#checking-results)
10. [Troubleshooting](#troubleshooting)
11. [Privacy & Security](#privacy--security)

---

## Overview

- **Distributed cracking** — leverages massive wordlists and shared compute
- **Free service** — no cost for basic usage
- **Multiple hash types** — WPA/WPA2 handshakes, PMKIDs, WPA3-SAE
- **Email notifications** — get alerted when a password is cracked
- **Complementary** — works alongside local cracking with hashcat / john

---

## Getting Your API Key

1. Visit [wpa-sec.stanev.org](https://wpa-sec.stanev.org)
2. Click **"Get your key"** and follow the registration steps
3. Keep your API key secure — it identifies your submissions

---

## Quick Start

```bash
# Enable wpa-sec uploads with your API key
sudo wifite --wpasec --wpasec-key YOUR_API_KEY

# Automatic upload mode (no prompts)
sudo wifite --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto

# Upload + email notification when cracked
sudo wifite --wpasec --wpasec-key YOUR_API_KEY --wpasec-email your@email.com

# Remove local capture files after successful upload
sudo wifite --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto --wpasec-remove
```

---

## All Options

| Option | Description |
|--------|-------------|
| `--wpasec` | Enable wpa-sec upload functionality |
| `--wpasec-key [key]` | Your wpa-sec.stanev.org API key (required for uploads) |
| `--wpasec-auto` | Upload all captures automatically without prompting |
| `--wpasec-url [url]` | Custom wpa-sec server URL (default: `https://wpa-sec.stanev.org`) |
| `--wpasec-timeout [sec]` | Connection timeout in seconds (default: 30) |
| `--wpasec-email [email]` | Email address for cracking notifications |
| `--wpasec-remove` | Delete capture files after successful upload |

---

## Upload Modes

### Interactive (default)

```bash
sudo wifite --wpasec --wpasec-key YOUR_API_KEY
```

Prompts after each successful capture.  Choose which handshakes to upload.

### Automatic

```bash
sudo wifite --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto
```

Uploads all captures without prompts.  Best for unattended sessions.

---

## Supported Capture Types

| Format | Description |
|--------|-------------|
| `.cap` / `.pcap` / `.pcapng` | WPA/WPA2 handshake captures |
| `.pcapng` (hcxdumptool) | PMKID captures |
| `.pcapng` (SAE) | WPA3-SAE handshake captures |
| `.gz` | Gzip-compressed captures |

> **Note:** wpa-sec accepts pcap/pcapng packet capture formats.  Hash files (`.22000`) are
> **not** supported for upload.

---

## Examples

```bash
# WPA attack with automatic upload
sudo wifite --wpa --wpasec --wpasec-key YOUR_API_KEY

# PMKID attack with automatic upload
sudo wifite --pmkid --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto

# WPA3 attack with email notifications
sudo wifite --wpa3-only --wpasec --wpasec-key YOUR_API_KEY --wpasec-email you@example.com

# Target a specific network and upload
sudo wifite -b AA:BB:CC:DD:EE:FF --wpasec --wpasec-key YOUR_API_KEY

# Dual interface mode with automatic upload
sudo wifite --dual-interface --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto
```

---

## Tool Requirements

WPA-SEC integration uses the `wlancap2wpasec` tool from the hcxtools suite:

```bash
# Kali Linux / Debian / Ubuntu
sudo apt update && sudo apt install hcxtools

# Arch Linux
sudo pacman -S hcxtools

# Verify
wlancap2wpasec --version
```

> `wlancap2wpasec` is optional — wifite works normally without it, but wpa-sec upload
> features will be unavailable.

---

## Checking Results

After uploading, visit [wpa-sec.stanev.org](https://wpa-sec.stanev.org) to:

- View your submission history
- Check cracking progress
- Download cracked passwords
- Manage your API key and settings

If you provided `--wpasec-email`, you'll receive a notification when a password is cracked.

---

## Troubleshooting

**"wlancap2wpasec not found"**  
Install hcxtools: `sudo apt install hcxtools`, then verify with `which wlancap2wpasec`.

**"Invalid API key"**  
Verify your key at wpa-sec.stanev.org.  Keys are case-sensitive with no extra spaces.

**"Upload failed: Connection timeout"**  
Check your internet connection; try `--wpasec-timeout 60`; verify wpa-sec.stanev.org is
reachable from your network.

**"No handshake in capture file"**  
Expected — wifite validates captures before upload.  Only valid handshakes/PMKIDs are sent.
Check capture quality with `tshark` or `aircrack-ng`.

**File not removed after upload**  
Ensure you used `--wpasec-remove`.  Files are removed only after a confirmed successful upload.

---

## Privacy & Security

**What gets uploaded:** capture files (handshakes/PMKIDs), target BSSID/ESSID, your API key.

**What does NOT get uploaded:** your IP address beyond normal HTTP headers, client device info,
cracked passwords (you retrieve those from the wpa-sec website).

**Best practices:**
- Only upload captures from networks you own or have explicit written authorization to test.
- Use `--wpasec-remove` to avoid leaving sensitive capture files on disk.
- Keep your API key private — do not commit it to scripts or share it publicly.
- Review the wpa-sec.stanev.org privacy policy and terms of service.

> **Legal reminder:** Uploading captures from unauthorized networks may be illegal in your
> jurisdiction.  Only test networks you are authorized to test.
