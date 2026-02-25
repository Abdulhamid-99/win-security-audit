# Windows Security Audit

One-command security assessment for Windows endpoints. Detects compromises, persistence mechanisms, unauthorized access, and misconfigurations — no installation required.

## Quick Start

**Double-click** `audit.bat` or run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/full-audit.ps1
```

A timestamped report is saved to `reports/`.

## What It Checks

| Category | Checks |
|---|---|
| **Antivirus** | Defender status, real-time protection, exclusion tampering, GPO overrides, third-party AV detection (Kaspersky, Norton, Bitdefender, ESET, etc.) |
| **Network** | Firewall status, listening ports mapped to processes, external connections mapped to processes, SMBv1 (EternalBlue), proxy MITM, network shares |
| **Persistence** | Registry Run/RunOnce keys (HKLM + HKCU), WMI event subscriptions, non-Microsoft scheduled tasks, services from non-standard paths |
| **Users & Access** | Local accounts, admin group members, RDP status, active sessions, SSH keys, recently added root certificates, hosts file hijacking |
| **Processes** | Processes running from Temp/AppData/unusual locations, OS patch level, last update date |

## Requirements

- Windows 10 / 11
- PowerShell 5.1+ (built-in)
- **No admin required** for most checks — some (Security event log, `netstat -b`) need elevation and will gracefully skip

## Usage

### Full audit with report

```powershell
powershell -ExecutionPolicy Bypass -File scripts/full-audit.ps1
```

Output goes to screen and saves to `reports/security-report_YYYY-MM-DD_HH-mm.txt`.

### Full audit without saving

```powershell
powershell -ExecutionPolicy Bypass -File scripts/full-audit.ps1 -SkipReport
```

### Individual modules

```powershell
# Antivirus / Defender
powershell -ExecutionPolicy Bypass -File scripts/defender-status.ps1

# Network connections, firewall, SMB, proxy
powershell -ExecutionPolicy Bypass -File scripts/network-audit.ps1

# Persistence: registry, WMI, scheduled tasks, services
powershell -ExecutionPolicy Bypass -File scripts/persistence-check.ps1

# User accounts, RDP, SSH keys, certificates, hosts file
powershell -ExecutionPolicy Bypass -File scripts/user-and-access.ps1

# Suspicious processes, OS version, patch level
powershell -ExecutionPolicy Bypass -File scripts/process-audit.ps1
```

## Output Example

```
WINDOWS ENDPOINT SECURITY AUDIT
Date     : 2026-02-25 22:30:00
Machine  : DESKTOP-ABC123
User     : JohnDoe
OS       : Microsoft Windows 11 Pro Build 26200

============================================================
  1. ANTIVIRUS / ENDPOINT PROTECTION
============================================================

--- Windows Defender Status ---
  Antivirus Enabled        : True
  Real-Time Protection     : True
  ...

--- Defender Exclusions ---
  No exclusions configured (clean)

--- Third-Party Antivirus ---
  Kaspersky Service 21.24 [Running] Start:Auto

============================================================
  2. NETWORK SECURITY
============================================================

--- Firewall Status ---
  Domain: ON
  Private: ON
  Public: ON

--- SMB Configuration ---
  SMBv1: Disabled (secure)
  ...
```

## Interpreting Results

| Marker | Meaning |
|---|---|
| `(clean)` | Check passed, nothing suspicious |
| `[!]` | Worth reviewing — may or may not be an issue |
| `[!!]` | Likely problem — investigate immediately |

Common false positives:
- Defender disabled when a third-party AV (Kaspersky, Bitdefender, etc.) is installed — this is normal
- Docker entries in hosts file (`host.docker.internal`) — normal
- Default admin shares (C$, ADMIN$, IPC$) — built into Windows

## Project Structure

```
security/
├── audit.bat              # Double-click to run
├── scripts/
│   ├── full-audit.ps1     # Main script — runs all modules
│   ├── defender-status.ps1
│   ├── network-audit.ps1
│   ├── persistence-check.ps1
│   ├── user-and-access.ps1
│   └── process-audit.ps1
└── reports/               # Auto-generated, gitignored
```

## License

MIT
