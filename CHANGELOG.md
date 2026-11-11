# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-11-11

3.0.0 is a corrective release: it makes reported success match what actually
happened on the wire, gives every radio change a single owner that can restore
it, and closes a large batch of correctness and security defects found during
live testing on Broadcom/Nexmon and mt76 hardware.

### Added

**Radio state and cleanup**
- A single radio-state supervisor now owns every interface mutation. Before the
  first write it snapshots ifindex, mode, channel, MAC and addresses; changes
  are applied once with exit status and read-back verification, and only the
  fields that changed are restored. Externally added IPs are preserved and
  failed restores are retried rather than dropped. Airmon, Iw, Ip, MAC,
  hostapd, dnsmasq, Evil Twin, WPA, WPA3, Nexmon and shutdown all run through
  it. Up/down is decided from `IFF_UP` instead of `operstate`.
- `Process.force_kill()` for processes that ignore SIGTERM.

**Nexmon / Broadcom FullMAC**
- Broadcom FullMAC Nexmon support: `nexutil` is probed, the driver lifecycle is
  guarded, and Nexmon is integrated into dependency and system checks.
- Firmware identification reads the revinfo string from
  `nexutil -I <if> -V` instead of `/sys/module/brcmfmac/version`.
- Hexdump parsing fallback for installations where `nexutil -R` is missing.
- Leaked `{station}mon` monitors are recovered, preferred monitor names are
  reused, and dual-interface candidates are deduplicated by PHY.
- Teardown happens before the rogue AP starts when Nexmon and Evil Twin share a
  radio.

**Scanning and channel handling**
- 6 GHz channel table and band-aware channel conversion; targets carry their
  frequency and band.
- 5 GHz band suffixes for hcxdumptool channel arguments.
- Scan diagnostics that explain why no targets were found instead of returning
  an empty list.
- `--random-mac` for a fully random interface MAC and `--random-mac-vendor`
  to randomize only the device part and keep the vendor bytes.

**Captures and cracking**
- Run-scoped capture cache: a PMKID run publishes its pcapng and the WPA stage
  reuses it instead of capturing again.
- 10-second PMKID grace window so a crackable EAPOL pair arriving just after
  the PMKID is not discarded.
- Negative crack cache keyed by `(BSSID, wordlist)`, so a known miss is not
  retried in the same run.
- hcxdumptool / hcxtools 8 and hashcat 8 support. hcxpcapngtool 7 dropped
  `--bssid`/`--essid`, so filtering now happens in Python (MAC_AP field 3,
  ESSID hex field 5) and output files are unlinked before conversion.
- Native Scapy PMKID capture fallback for adapters where hcxdumptool fails to
  arm the interface.

**CLI**
- `--version`.
- `--ignore-captured` to skip networks that already have a capture on disk.
- `--dict` accepts a directory of wordlists.
- `--kalidroid` MiniTerminal output.

**Safety**
- `mask_sensitive()` redacts passwords and PSKs (CWE-312), showing only the
  first two characters.

### Changed

**Update behaviour**
- Wifite no longer updates itself. The startup check only reports that a newer
  commit exists and points at `--update`.

**hcxdumptool**
- Headless capture: the display that was previously forced on and then piped
  away is no longer requested, and a capture that stops early now reports why
  (including watchdog exits) instead of looking like a timeout.
- `-A` is only passed with `--hcxdump-active`, with a warning on mt76.
- macchanger is skipped for hcxdumptool runs; `IFF_PROMISC`/`IFF_ALLMULTI` are
  snapshotted and restored instead of being tracked in a ledger.
- Wifite-owned monitor interfaces are handed back to managed mode for the run
  and re-armed on exit, because hcxdumptool 7+ owns the monitor lifecycle.
  This applies only where hcxdumptool is the sole user of the interface.

**Cracking**
- OpenCL devices are probed once; hashcat then runs with `-D 1`, retrying once
  when a device fails. Wordlists are tried smallest-first.
- hashcat exit codes are classified: 0/1 are normal, 2 is an abort, and
  3/4/255 are reported as run errors.
- WPS and WPA3 analysis is batched and cached per capture rather than spawning
  one tshark process per target.

**Targets and sessions**
- Handshakes require a crackable pair (M1+M2 or M2+M3) *and* a
  `WPA*02`/`03`/`04` record from hcxpcapngtool.
- A new `captured` session status distinguishes "captured but not cracked"
  from "no capture".
- `--wps-only` only skips targets that are known non-WPS.

**Performance**
- Airodump lookup rewritten from O(n·m) to O(n); chardet samples 4 KB instead
  of the whole file; the OUI database is loaded lazily.
- Credential validation uses selectors-based reads instead of polling.
- Attack monitor entries are pruned by TTL, so long runs no longer grow without
  bound.

**Structure**
- `config.py` split into a `config/` package: defaults, validators,
  manufacturers and nine parser modules.

**Dependencies**
- Wifite no longer prompts to install missing optional dependencies such as
  hashcat.
- hcxdumptool and hcxpcapngtool 7.0.0 are required; binaries from different
  suite releases are reported, and WPA-FT requires hashcat 8.0.0 or newer.
- Readiness now reports capture and cracking separately, so a missing cracker
  no longer marks capture as unavailable.

### Fixed

**Truthful reporting**
- A complete 4-way handshake is no longer reported as partial.
- PMKID network counts are derived from the capture rather than from the hashes
  that survived conversion.
- WPA3/SAE captures are no longer presented as offline-crackable; the
  limitation is stated explicitly. An SAE capture counts as complete only when
  both Commit (seq 1) and Confirm (seq 2) were seen, and `--no-downgrade` /
  `--force-sae` are actually consulted.
- A capture that could not be tested is reported as untested instead of as a
  wordlist miss.
- `--resume-id` names the session that was not found.

**Radio and cleanup**
- Cleanup survives `EBUSY` when the driver refuses a mode change.
- The `-i` path no longer skips `Airmon.ask()`, which previously left brcmfmac
  scanning with zero frames.
- Channel read-back is retried in dual-interface mode.
- Cleanup runs on `SIGTERM`.

**Nexmon**
- Failed PMKID captures on brcmfmac now fail fast with the real error rather
  than after a full timeout.

**Evil Twin**
- The rogue AP is now open. hostapd previously forced WPA2, so victims could
  never associate.
- dnsmasq is started with `except-interface=lo` and its errors are read from
  stderr.
- The dual-interface assignment import was fixed; a `ModuleNotFoundError`
  previously collapsed every run to single-interface.
- Portal startup has a single setup path, safe credential configs, cleanup
  after a failed start, and a free-port fallback.

**Cracking**
- `--wps-only` no longer skipped non-WPS targets (`WPSState` compared as an int
  instead of `is False`).
- The 4-way stage is no longer skipped after a PMKID capture.
- `AttackPMKID.run` had a missing return; `Process.exists` had an operator
  precedence bug; `Process.call` mis-split string arguments; several latent
  `NameError`s were removed.
- WPS options are honoured on resume, with `--no-pixie` and `--no-nullpin`
  independent of each other.
- WEP fakeauth has a timeout instead of hanging.

### Security

- Removed `shell=True` escalation paths and string-concatenated hashcat
  commands (command injection).
- Closed file-handle leaks, including in `Process.devnull()`.
- Fixed temp-file TOCTOU and umask handling.
- Made process-manager ordering deterministic.
- Redacted passwords and PSKs from logs and output.

### Removed

- Automatic self-update from `origin/master` (replaced by the check-only
  notice and `--update`).
- hcxpcapngtool `--bssid`/`--essid` invocation, superseded by Python-side
  filtering for hcxtools 7+.

## [2.9.9-beta] - 2025-10-27

This line was released from commit `41ee252d2` and was never tagged; the
section boundary sits at that commit.

### Added
- Terminal UI (`--tui`) with session, resume and clean support.
- DragonBlood (WPA3) attack support and OWO network detection.
- Evil Twin, WPA3-SAE and adaptive deauthentication attacks.
- Logging with exception handling.

### Changed
- README rewritten for the 2.9.x feature set.

## [2.8.2] - 2025-10-25

See the [`2.8.2` tag](https://github.com/derv82/wifite2/releases/tag/2.8.2).

[3.0.0]: https://github.com/derv82/wifite2/compare/2.8.2...3.0.0
[2.9.9-beta]: https://github.com/derv82/wifite2/compare/2.8.2...41ee252d2
[2.8.2]: https://github.com/derv82/wifite2/releases/tag/2.8.2