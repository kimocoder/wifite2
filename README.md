[![GitHub version](https://img.shields.io/badge/version-2.9.9--beta-informational.svg)](#)
[![GitHub issues](https://img.shields.io/github/issues/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/issues)
[![GitHub forks](https://img.shields.io/github/forks/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/network)
[![GitHub stars](https://img.shields.io/github/stars/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/stargazers)
[![Android Supported](https://img.shields.io/badge/Android-Supported-green.svg)](#)
[![GitHub license](https://img.shields.io/github/license/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/blob/master/LICENSE)


Wifite2
=======

A complete rewrite of [`wifite`](https://github.com/derv82/wifite), a Python tool for
auditing wireless networks — originally by [@derv82](https://github.com/derv82),
currently maintained by [@kimocoder](https://github.com/kimocoder).

Wifite runs existing wireless-auditing tools for you. Stop memorising command arguments &
switches! Select your targets and Wifite will automatically try to capture or crack the
password using all known methods:

1. **WPS** – Pixie-Dust (offline), Online Brute-Force PIN, NULL PIN
2. **WPA/WPA2** – 4-way Handshake capture + offline crack
3. **WPA/WPA2** – PMKID capture + offline crack
4. **WPA3-SAE** – SAE Handshake capture + offline crack
5. **WPA3 Transition Mode** – Downgrade to WPA2 on mixed networks
6. **WEP** – Fragmentation, chop-chop, ARP replay, caffe-latte, p0841, hirte
7. **Evil Twin** – Rogue AP with captive portal for credential capture

Topics: `aircrack-ng` · `bully` · `cowpatty` · `hashcat` · `hcxtools` · `john` ·
`kali-linux` · `nethunter` · `reaver` · `tshark` · `wifite2`

---

## ⚠️ Legal Disclaimer

**This tool is for authorised security testing and educational purposes only.**
Only use wifite2 on networks you own or have **explicit written permission** to test.
Unauthorised access to computer networks is illegal in most jurisdictions.
The authors assume no liability for misuse.

---

## Supported Operating Systems

| Platform | Status |
|----------|--------|
| Kali Linux | ✅ Fully supported (primary dev platform) |
| ParrotSec | ✅ Fully supported |
| BlackArch | ✅ Fully supported |
| Kali NetHunter (Android) | 📱 Supported – requires kernel with monitor mode |
| Ubuntu / Debian | ⚠️ Partial – manual tool install needed |
| Arch Linux | ⚠️ Partial – AUR packages required |
| Other Linux | ⚠️ Possible – ensure latest tool versions |

---

## Requirements

- **Python 3.10+** (tested up to Python 3.14)
- **Wireless adapter** with monitor mode and packet injection support
- **Root / sudo** access

---

## Required Tools

A monitor-mode-capable adapter is essential.
Check [compatible cards](https://www.aircrack-ng.org/doku.php?id=compatible_cards).

**Required:**

| Tool | Purpose |
|------|---------|
| [`iw`](https://wireless.wiki.kernel.org/en/users/documentation/iw) | Identify monitor-mode interfaces |
| [`ip`](https://packages.debian.org/buster/net-tools) | Start / stop wireless devices |
| [`aircrack-ng` suite](https://aircrack-ng.org/) | Monitor mode, packet capture, WEP/WPA cracking (`airmon-ng`, `aircrack-ng`, `aireplay-ng`, `airodump-ng`, `packetforge-ng`) |

**Optional (recommended):**

| Tool | Purpose |
|------|---------|
| [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html) | Handshake verification, WPS detection, attack monitoring |
| [`reaver`](https://github.com/t6x/reaver-wps-fork-t6x) | WPS Pixie-Dust & PIN attacks |
| [`bully`](https://github.com/aanarchyy/bully) | Alternative WPS attack tool (`--bully`) |
| [`pixiewps`](https://github.com/wiire-a/pixiewps) | Offline WPS Pixie-Dust |
| [`hashcat`](https://hashcat.net/) | GPU cracking of PMKID / WPA3-SAE hashes |
| [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool) | PMKID and WPA3-SAE capture (v6.0.0+) |
| [`hcxpcapngtool`](https://github.com/ZerBea/hcxtools) | Convert captures to hashcat format (v6.0.0+) |
| [`john`](https://www.openwall.com/john) | CPU/GPU wordlist cracking |
| [`coWPAtty`](https://tools.kali.org/wireless-attacks/cowpatty) | Handshake verification |
| [`macchanger`](https://github.com/alobbs/macchanger) | MAC address randomisation |

**For Evil Twin attacks:**

| Tool | Minimum Version |
|------|----------------|
| [`hostapd`](https://w1.fi/hostapd/) | 2.9 |
| [`dnsmasq`](http://www.thekelleys.org.uk/dnsmasq/doc.html) | 2.80 |
| [`wpa_supplicant`](https://w1.fi/wpa_supplicant/) | 2.9 |

---

## Installation

### Quick install (recommended)

```bash
git clone https://github.com/kimocoder/wifite2.git
cd wifite2
sudo python3 setup.py install
sudo wifite
```

### Poetry (developers)

```bash
git clone https://github.com/kimocoder/wifite2.git && cd wifite2
pip install poetry
poetry install
sudo poetry run wifite
```

### pip / venv

```bash
git clone https://github.com/kimocoder/wifite2.git && cd wifite2
python3 -m venv venv && source venv/bin/activate
pip3 install -r requirements.txt
sudo python3 wifite.py
```

### Package manager

```bash
# Kali Linux / Debian
sudo apt update && sudo apt install wifite

# Arch Linux (AUR)
yay -S wifite2-git
```

### Verify installation

```bash
sudo wifite --syscheck
```

`--syscheck` reports: root status, RF-Kill, conflicting processes, tool availability,
interface capabilities, and attack readiness for each attack type.

---

## Quick Start

```bash
# Default scan and attack
sudo wifite

# Attack only WPA3 networks
sudo wifite --wpa3-only

# Fastest WPA/WPA2 — PMKID (no connected clients needed)
sudo wifite --pmkid

# Passive PMKID sniffing across all nearby networks
sudo wifite --pmkid-passive

# Evil Twin rogue AP attack
sudo wifite --eviltwin

# Dual-interface mode (two adapters, 30–50 % faster)
sudo wifite --dual-interface

# Passively monitor for wireless attacks (deauth / disassoc)
sudo wifite --monitor-attacks --monitor-duration 3600

# Upload captures to wpa-sec for distributed cracking
sudo wifite --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto

# Resume an interrupted session
sudo wifite --resume

# Show cracked networks from previous sessions
sudo wifite --cracked

# Crack a previously captured handshake
sudo wifite --crack --dict /path/to/wordlist.txt

# Show all options
sudo wifite -h -v
```

---

## Features

### Attack methods

- **WPS** – Pixie-Dust, online PIN brute-force, NULL PIN
  (`--wps-only`, `--pixie`, `--no-pixie`, `--bully`, `--no-wps`)
- **WPA/WPA2** – Handshake capture + offline crack (`--wpa`, `--no-wps`, `--dict`)
- **PMKID** – Clientless WPA2 attack (`--pmkid`, `--pmkid-passive`)
- **WPA3-SAE** – Handshake capture and transition-mode downgrade
  (`--wpa3-only`, `--force-sae`, `--no-downgrade`, `--check-dragonblood`, `--wpa3-timeout`)
  → [WPA3 Guide](docs/WPA3_GUIDE.md)
- **WEP** – Fragmentation, chop-chop, ARP replay, caffe-latte, p0841, hirte (`--wep`)
- **Evil Twin** – Rogue AP + captive portal (`--eviltwin`)
  → [Evil Twin Guide](docs/EVILTWIN_GUIDE.md)

### Targeting & scanning

- `-5` — include 5 GHz channels
- `-c [channels]` — scan specific channels (e.g. `-c 1,3-6`)
- `-b [bssid]` / `-e [essid]` — target a specific AP
- `--clients-only` — only attack APs with associated clients
- `--detect-honeypots` — flag potential rogue/honeypot APs
- Hidden SSID decloaking during attacks

### Dual interface support

Use two wireless adapters simultaneously for parallel operations (no mode switching,
30–50% faster Evil Twin and WPA attacks).
→ [Dual Interface Guide](docs/DUAL_INTERFACE_GUIDE.md) · [Examples](docs/DUAL_INTERFACE_EXAMPLES.md)

```bash
sudo wifite --dual-interface
sudo wifite --interface-primary wlan0 --interface-secondary wlan1
```

### Wireless attack monitoring

Passively detect deauth / disassoc frames in real time with a live TUI dashboard.
Requires `tshark`.
→ [Attack Monitoring Guide](docs/ATTACK_MONITORING_GUIDE.md)

```bash
sudo wifite --monitor-attacks                              # infinite
sudo wifite --monitor-attacks --monitor-duration 300       # 5 minutes
sudo wifite --monitor-attacks --monitor-channel 6          # single channel
sudo wifite --monitor-attacks --monitor-hop                # all 2.4 GHz channels
sudo wifite --monitor-attacks --monitor-log attacks.log    # log to file
```

### WPA-SEC integration

Upload captured handshakes / PMKIDs to [wpa-sec.stanev.org](https://wpa-sec.stanev.org)
for distributed cracking.
→ [WPA-SEC Guide](docs/WPASEC_GUIDE.md)

```bash
sudo wifite --wpasec --wpasec-key YOUR_API_KEY
sudo wifite --wpasec --wpasec-key YOUR_API_KEY --wpasec-auto --wpasec-remove
```

### Session resume

Automatically save and resume interrupted attack sessions.
→ [Resume Guide](docs/RESUME_GUIDE.md)

```bash
sudo wifite --resume            # interactive session picker
sudo wifite --resume-latest     # resume most recent session
sudo wifite --resume-id <id>    # resume by session ID
sudo wifite --clean-sessions    # remove sessions older than 7 days
```

### Convenience

- `--syscheck` — full system readiness check
- `--cracked` — show previously cracked networks
- `--crack` — show hashcat / aircrack commands for a captured handshake
- `--no-tui` — classic text mode (no TUI dashboard)
- `--num-deauths [n]` / `--no-deauths` — control deauthentication behaviour
- `-v` / `-vv` / `-vvv` — increasing verbosity; shows commands and tool output
- `-mac` / `--random-mac` — randomise MAC address before attacking

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Evil Twin Guide](docs/EVILTWIN_GUIDE.md) | Rogue AP + captive portal – requirements, usage, templates |
| [Evil Twin Troubleshooting](docs/EVILTWIN_TROUBLESHOOTING.md) | Common Evil Twin errors and fixes |
| [Dual Interface Guide](docs/DUAL_INTERFACE_GUIDE.md) | Two-adapter mode – setup and usage |
| [Dual Interface Examples](docs/DUAL_INTERFACE_EXAMPLES.md) | Practical dual-interface command examples |
| [WPA3 Guide](docs/WPA3_GUIDE.md) | WPA3 attack strategies, usage, tool requirements |
| [WPA3 Troubleshooting](docs/WPA3_TROUBLESHOOTING.md) | WPA3-specific issues and PMF handling |
| [WPA3 Detection Optimization](docs/WPA3_DETECTION_OPTIMIZATION.md) | Improving WPA3 detection accuracy |
| [Attack Monitoring Guide](docs/ATTACK_MONITORING_GUIDE.md) | Passive deauth/disassoc detection – TUI, logs, FAQ |
| [WPA-SEC Guide](docs/WPASEC_GUIDE.md) | Uploading captures to wpa-sec.stanev.org |
| [Resume Guide](docs/RESUME_GUIDE.md) | Session save/resume internals and troubleshooting |
| [TUI Guide](docs/TUI_README.md) | Interactive text user interface usage |

---

## Troubleshooting

**Permission denied / not root** — always run with `sudo`.

**Interface not found** — run `sudo airmon-ng` to list interfaces; enable monitor mode with
`sudo airmon-ng start <iface>`; try `--kill` to stop conflicting processes.

**WPS attacks failing** — ensure `reaver` and/or `bully` are installed and up-to-date;
try `--pixie` for Pixie-Dust only.

**Handshake capture issues** — ensure clients are connected; increase deauths with
`--num-deauths`; try a longer attack timeout.

**WPA3 issues** — see [WPA3 Troubleshooting](docs/WPA3_TROUBLESHOOTING.md).

**Evil Twin issues** — see [Evil Twin Troubleshooting](docs/EVILTWIN_TROUBLESHOOTING.md).

**Attack monitoring issues** — ensure `tshark` is installed; see
[Attack Monitoring Guide](docs/ATTACK_MONITORING_GUIDE.md).

Enable verbose output for debugging: `-v`, `-vv`, or `-vvv`.

For further help, [open an issue](https://github.com/kimocoder/wifite2/issues) and include
your OS, wireless card model / chipset, and full output with `-vvv`.

---

## Contributing

Contributions are welcome!

- **Bugs:** Use the [issue tracker](https://github.com/kimocoder/wifite2/issues); include
  OS, wireless card model, and output with `-vvv`.
- **Code:** Fork the repo, create a feature branch, follow existing code style, add tests
  where appropriate, and submit a pull request with a clear description.
- **Docs:** Improve guides, add examples, fix typos, or translate documentation.
- **Testing:** Report compatibility findings for specific hardware or distributions.

---

## License

GPL-2.0 – see [LICENSE](LICENSE).

---

## Credits

- **Original author:** [@derv82](https://github.com/derv82) – created the original `wifite`
- **Current maintainer:** [@kimocoder](https://github.com/kimocoder)
- **Tool authors:** aircrack-ng team, ZerBea (hcxtools / hcxdumptool), hashcat team,
  reaver / bully / pixiewps authors, Wireshark Foundation, and all other open-source
  contributors whose tools make wifite2 possible
- **Security research:** Mathy Vanhoef (KRACK, Dragonblood, FragAttacks)
- **Community:** All contributors who submitted PRs, reported issues, and tested features —
  thank you!
