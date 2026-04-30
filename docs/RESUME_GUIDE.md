# Session Resume Guide

Wifite2 automatically saves attack progress and lets you resume interrupted sessions after
a Ctrl+C, crash, or power loss.

## Table of Contents

1. [Overview](#overview)
2. [Basic Usage](#basic-usage)
3. [How It Works](#how-it-works)
4. [Session Management](#session-management)
5. [What Is (and Is Not) Saved](#what-is-and-is-not-saved)
6. [Troubleshooting](#troubleshooting)

---

## Overview

- Sessions are saved automatically after each target completion
- Session files are stored in `~/.wifite/sessions/` with restricted permissions (600)
- Multiple sessions can be managed via an interactive selection interface
- Sessions older than 7 days are cleaned up automatically on startup

---

## Basic Usage

```bash
# Start any attack — progress is saved automatically
sudo wifite

# If interrupted, resume with an interactive session picker
sudo wifite --resume

# Resume the most recent session automatically (no prompt)
sudo wifite --resume-latest

# Resume a specific session by ID
sudo wifite --resume-id session_20250126_120000
```

---

## How It Works

1. **Automatic saving** — progress is written to disk after each target is completed or skipped.
2. **Session files** — stored as JSON in `~/.wifite/sessions/` (permissions: 600).
3. **Smart filtering** — when resuming, already-completed and failed targets are skipped automatically.
4. **Configuration restore** — the original attack parameters (wordlist, timeouts, attack types) are restored from the session file.
5. **Interface handling** — if the original interface is no longer available, wifite prompts you to use the current one instead.

---

## Session Management

```bash
# List available sessions and choose one interactively
sudo wifite --resume

# Remove old session files (older than 7 days)
sudo wifite --clean-sessions
```

Session IDs follow the format `session_YYYYMMDD_HHMMSS`.  Use `--resume` to see available
IDs, then pass one to `--resume-id` for non-interactive resumption.

---

## What Is (and Is Not) Saved

### Saved

- Target list and per-target attack progress
- Completed and failed targets
- Attack configuration (wordlist path, timeouts, enabled attack types)
- Original interface name and settings

### NOT saved (for security)

- Captured passwords or keys
- Handshake files (`.cap` / `.pcapng`)
- PMKID hashes

---

## Troubleshooting

**No session files found**  
Sessions are created after target selection.  Start a new attack first.
Check that `~/.wifite/sessions/` exists and has correct ownership.

**Corrupted session file**  
Wifite detects corruption automatically and offers to delete the file.
Use `--clean-sessions` to manually remove problematic sessions.

**Original interface unavailable**  
Wifite will detect this and prompt you to substitute the current interface.

**Session not resuming correctly**  
Ensure you are running the same version of wifite.  Check that all required tools are
still installed.  Use `--resume` to inspect session details before confirming.
