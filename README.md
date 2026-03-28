# PS-KUD

Pure PowerShell Kerberos Unconstrained Delegation monitor. A port of Rubeus's `monitor` command with zero external dependencies — just PowerShell and native Windows APIs. For more information about the code itself, check my [article](https://blog.y00ga.lol/PERSO/PUBLISH/Article+perso/PS-KUD+-+or+How+I+Learned+to+Stop+Packing+and+Love+the+TGT)

## What it does

Continuously polls all logon sessions on the local machine for new Ticket Granting Tickets (TGTs). When a previously unseen TGT appears, it extracts the full `.kirbi` blob and displays it as base64. Optionally performs automatic Pass-the-Ticket injection.

Primary use case: capturing incoming TGTs on servers with **unconstrained delegation** enabled.

## Requirements

- PowerShell 5.1+
- **Administrator** (elevated) session

## Usage

```powershell
# Basic — poll every 60s for any new TGT
.\Invoke-PSKUD.ps1

# Poll every 10 seconds
.\Invoke-PSKUD.ps1 -Interval 10

# Filter for a specific user, single-line base64 output
.\Invoke-PSKUD.ps1 -Interval 5 -TargetUser "admin" -NoWrap

# Capture a machine account TGT and auto-inject it (Pass-the-Ticket)
.\Invoke-PSKUD.ps1 -Interval 5 -TargetUser 'DC01$' -Import

# Run for 5 minutes then stop
.\Invoke-PSKUD.ps1 -Interval 5 -RunFor 300

# Persist captured tickets to the registry
.\Invoke-PSKUD.ps1 -RegistryPath "SOFTWARE\TGTCaptures"
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Interval` | int | 60 | Polling interval in seconds |
| `-TargetUser` | string | *(all)* | Case-insensitive substring filter on username |
| `-NoWrap` | switch | off | Output base64 as a single unwrapped line |
| `-Import` | switch | off | Auto-inject each captured TGT into the current logon session (PTT) |
| `-RunFor` | int | 0 | Stop after N seconds (0 = run indefinitely) |
| `-RegistryPath` | string | *(none)* | Persist captured TGTs under `HKLM:\<path>` as base64 registry values |

## How it works

https://github.com/user-attachments/assets/c283a6a2-2305-4881-b81f-45176b250c0a

1. Elevates to SYSTEM by duplicating the `winlogon.exe` token
2. Connects to the LSA via `LsaConnectUntrusted`
3. Enumerates all logon sessions with `LsaEnumerateLogonSessions`
4. For each session, queries the Kerberos ticket cache (`KerbQueryTicketCacheExMessage`)
5. Extracts `krbtgt/*` tickets as KRB-CRED (`.kirbi`) blobs via `KerbRetrieveEncodedTicketMessage`
6. Deduplicates by base64 content and displays new tickets
7. Optionally injects via `KerbSubmitTicketMessage` (Pass-the-Ticket)

All interop is done through inline C# compiled with `Add-Type` — no external binaries.
