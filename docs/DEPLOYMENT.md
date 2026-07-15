# CII ADSync — Production Deployment Runbook

A task-oriented guide for standing up the Cisco Identity Intelligence (CII) Active
Directory sync as a reliable, repeatable, scheduled job on a Windows Server.

This runbook is the **operational companion** to the [README](../README.md). The README
is the reference for *what the scripts do and how to customize them*; this document is the
*deployment procedure* and the production hardening around it. Where the two overlap, this
runbook links back to the README rather than repeating it.

> **New here?** Skip to the [Quickstart checklist](#2-quickstart--required-task-checklist)
> and work top to bottom. Every box maps to a section below.

---

## Contents

1. [Overview & architecture](#1-overview--architecture)
2. [Quickstart — required-task checklist](#2-quickstart--required-task-checklist)
3. [Prerequisites](#3-prerequisites)
4. [Create the dedicated service account](#4-create-the-dedicated-service-account)
5. [Provision credentials (one-time)](#5-provision-credentials-one-time)
6. [Secure the credential artifacts](#6-secure-the-credential-artifacts)
7. [Validate with preview mode](#7-validate-with-preview-mode)
8. [Deploy the scheduled task](#8-deploy-the-scheduled-task)
9. [Reliability, logging & monitoring](#9-reliability-logging--monitoring)
10. [Operations: change management, DR & rotation](#10-operations-change-management-dr--rotation)
11. [Troubleshooting](#11-troubleshooting)
12. [Appendix: reference tables](#12-appendix-reference-tables)

---

## 1. Overview & architecture

The integration is two PowerShell scripts plus an optional customization file — no agent,
no service, no database:

| File | Role |
|------|------|
| [`Provision.ps1`](../Provision.ps1) | One-time: encrypts the CII API credentials into a key + config pair. |
| [`ADSync.ps1`](../ADSync.ps1) | The sync engine: reads AD, classifies users, pushes to CII via SCIM. |
| [`ADSync.Config.psd1`](../ADSync.Config.psd1) | Optional: classification/filtering customization. |
| [`Deploy-ADSync.ps1`](../Deploy-ADSync.ps1) | **This runbook's installer** — folder, ACLs, batch-logon right, scheduled task. |
| [`Run-ADSync.ps1`](../Run-ADSync.ps1) | **This runbook's task wrapper** — log retention + event-log alerting. |

Data flow:

```
                    (read, integrated auth or LDAP bind)
   Active Directory  ────────────────────────────►  ADSync host (member server)
   (Domain Controller)     LDAP 389 / Kerberos 88            │
                           ADWS 9389 / GC 3268 (opt)         │  ADSync.ps1
                                                             ▼
                                          Cisco Identity Intelligence (cloud)
                                          OAuth token URL + SCIM base URL, HTTPS 443
```

Run it **once every 24 hours** during a quiet window. The host is any domain-member server
— it does **not** need to be a Domain Controller.

---

## 2. Quickstart — required-task checklist

Work through these in order. Details for each are in the linked sections.

- [ ] **Choose the host** — a domain-member Windows Server with line of sight to a DC and outbound HTTPS to CII. ([§3](#3-prerequisites))
- [ ] **Install prerequisites** — PowerShell 5.1+ and the RSAT `ActiveDirectory` module. ([§3](#3-prerequisites))
- [ ] **Open firewall paths** — AD ports to a DC; outbound 443 to the CII endpoints. ([§3](#3-prerequisites), [§12](#12-appendix-reference-tables))
- [ ] **Create the CII integration** in the CII UI and **download the credentials JSON**. ([README §Installation](../README.md#installation-and-setup))
- [ ] **Create the dedicated service account** (standard domain account or gMSA). ([§4](#4-create-the-dedicated-service-account))
- [ ] **Copy the scripts** to the host (e.g. `C:\ADSync`). ([§5](#5-provision-credentials-one-time))
- [ ] **Run `Provision.ps1` once** to produce the encrypted key + config. ([§5](#5-provision-credentials-one-time))
- [ ] **Delete the plaintext credentials JSON** (Provision offers to do this). ([§5](#5-provision-credentials-one-time))
- [ ] **Lock down the key/config files and folder** (done for you by `Deploy-ADSync.ps1`). ([§6](#6-secure-the-credential-artifacts))
- [ ] **Preview** — run `ADSync.ps1 -Preview` and review the output. ([§7](#7-validate-with-preview-mode))
- [ ] **Apply customizations** (`.psd1`) if the preview shows anything to tune. ([README §Customization](../README.md#customization-and-configuration))
- [ ] **Run one manual full sync** to confirm data reaches CII. ([§7](#7-validate-with-preview-mode))
- [ ] **Register the scheduled task** with `Deploy-ADSync.ps1`. ([§8](#8-deploy-the-scheduled-task))
- [ ] **Verify the scheduled run** and wire up monitoring/alerting. ([§9](#9-reliability-logging--monitoring))
- [ ] **Confirm identities in the CII UI** (allow up to 24h for first ingest). ([README §Data Processing](../README.md#data-processing-and-ui-update))

---

## 3. Prerequisites

**Host**
- Windows Server, **domain-joined**, any member server (not necessarily a DC).
- **Windows PowerShell 5.1 or later**.
- **RSAT `ActiveDirectory` module** (`ADSync.ps1` declares `#requires -Module ActiveDirectory`).
  `Deploy-ADSync.ps1` installs it automatically; to do it by hand:
  ```powershell
  # Windows Server
  Install-WindowsFeature RSAT-AD-PowerShell
  # Windows client / Server 2019+ Features-on-Demand
  Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
  ```

**Network / firewall** — the script pre-flights these and warns if a required port is unreachable:

| Direction | Port | Protocol | Required | Purpose |
|-----------|------|----------|----------|---------|
| Host → DC | 389 | LDAP | ✅ | Directory reads |
| Host → DC | 88 | Kerberos | ✅ | Integrated auth |
| Host → DC | 9389 | ADWS | ✅ | `ActiveDirectory` module |
| Host → DC | 3268 | Global Catalog | ➖ optional | Cross-domain lookups |
| Host → CII | 443 | HTTPS | ✅ | OAuth token URL + SCIM base URL |

- TLS 1.2/1.3 is enforced by the scripts — no manual `SchUseStrongCrypto` needed.
- **Behind an outbound proxy?** Set the proxy for the account that runs the task (e.g.
  `netsh winhttp set proxy` or a system-level `[System.Net.WebRequest]::DefaultWebProxy`).
  The token/SCIM endpoints must be reachable from the *scheduled task's* identity.

**Cisco Identity Intelligence**
- An Active Directory integration created in the CII UI, with the credentials JSON
  downloaded (contains `clientId`, `clientSecret`, `tokenUrl`, `scimBaseUrl`).

---

## 4. Create the dedicated service account

Run the sync under a **dedicated, least-privilege account** — never a personal admin login.
The account needs only **read** access to AD (which most accounts already have) and the
**"Log on as a batch job"** user right. It must **not** be a domain admin and the task must
**not** run "with highest privileges."

Pick one of the two models below.

### 4a. Standard domain service account (baseline)

Create the account (run on a DC or a host with RSAT, as an account allowed to create users):

```powershell
$pw = Read-Host -AsSecureString "Strong password for svc_cii_adsync"
New-ADUser `
    -Name              "svc_cii_adsync" `
    -SamAccountName    "svc_cii_adsync" `
    -UserPrincipalName "svc_cii_adsync@corp.example.com" `
    -Path              "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -AccountPassword   $pw `
    -PasswordNeverExpires $true `
    -CannotChangePassword $true `
    -Enabled           $true `
    -Description       "Cisco Identity Intelligence AD Sync (scheduled task)"
```

Guidance:
- **Store the password in your enterprise vault.** If you do not set `PasswordNeverExpires`,
  document a rotation cadence and remember to update the scheduled task when it changes
  (or use a gMSA — §4b — to avoid this entirely).
- **AD read access:** default *Authenticated Users* read is normally sufficient. If your
  directory has hardened ACLs that deny broad reads, grant this account read on the OUs you
  sync. If the task's own identity still cannot read AD, `ADSync.ps1` accepts explicit bind
  credentials via `-LdapUsername` / `-LdapPassword` as a fallback (avoid this if possible —
  it puts a password on the command line).
- **Do not** add the account to `Administrators`, `Domain Admins`, or any privileged group.
- **Optional hardening:** deny interactive and network logon for this account via Group
  Policy (`Deny log on locally`, `Deny log on through Remote Desktop Services`) so it can
  *only* run as a batch job.

The **"Log on as a batch job"** right is granted for you by `Deploy-ADSync.ps1` (§8). To do
it manually instead: `secpol.msc` → *Local Policies* → *User Rights Assignment* → **Log on
as a batch job** → add the account. In a domain, prefer a GPO so it survives rebuilds.

### 4b. Group Managed Service Account (gMSA) — recommended hardening

A gMSA has an AD-managed, auto-rotating password you never see or store. It is the more
secure and more repeatable choice for production.

```powershell
# Once per forest (if not already present). In production the key is usable after ~10h;
# -EffectiveImmediately is for labs only.
Add-KdsRootKey -EffectiveImmediately

# Create the gMSA and authorize THIS host's computer account to retrieve its password.
New-ADServiceAccount -Name "svc-ciiadsync" `
    -DNSHostName "svc-ciiadsync.corp.example.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "ADSYNC-HOST01$"

# On the ADSync host:
Install-ADServiceAccount -Identity "svc-ciiadsync"
Test-ADServiceAccount     -Identity "svc-ciiadsync"   # should return True
```

Then deploy with the gMSA (note the trailing `$` and `-Gmsa`):

```powershell
.\Deploy-ADSync.ps1 -ServiceAccount "CORP\svc-ciiadsync$" -Gmsa `
    -KeyFilePath .\cii-adsync-encryption.key `
    -ConfigFilePath .\cii-adsync-encrypted-config.json
```

**gMSA caveats:**
- A gMSA **cannot run the interactive `Provision.ps1`** step (§5). Provision under an
  administrator/interactive account, then hand the resulting key + config to the deployment.
- The gMSA still needs **read** NTFS access to the key and config files — `Deploy-ADSync.ps1`
  grants exactly this when you pass the gMSA as `-ServiceAccount`.

---

## 5. Provision credentials (one-time)

Do this once per host, under an interactive administrator session (see the gMSA caveat above).

1. Create the install directory and copy `Provision.ps1`, `ADSync.ps1`, `Run-ADSync.ps1`,
   `Deploy-ADSync.ps1`, and (optionally) your `ADSync.Config.psd1` into it — e.g. `C:\ADSync`.
2. Copy the credentials JSON you downloaded from CII into the same folder.
3. Encrypt it:

   ```powershell
   cd C:\ADSync
   .\Provision.ps1 -InputConfigPath .\cii-ad-<integration>-config.json
   ```

   This validates the credentials against CII, then writes two files:
   - `cii-ad-<integration>-encryption.key` — a 32-byte AES key.
   - `cii-ad-<integration>-encrypted-config.json` — the encrypted client ID/secret plus the
     token and SCIM endpoints.

4. When prompted, **delete the original plaintext JSON** (you can re-download it from CII any
   time). Confirm no other copies remain (Downloads, email, shares).

> If a script is blocked as "not digitally signed", allow it for the current session only:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. The scheduled task runs with
> `-ExecutionPolicy Bypass` for the same reason (see [README §Troubleshooting](../README.md#troubleshooting)).

---

## 6. Secure the credential artifacts

**Understand the security model.** The client ID/secret are encrypted with an AES key that
lives in the `.key` file. Protection therefore rests on **who can read that key file** — not
on machine-binding. Anyone who obtains **both** the `.key` file and the encrypted config can
decrypt the secret. So:

- Keep the key and encrypted config **on the host only**; do not email, share, or check them
  into source control.
- **Restrict NTFS permissions** on both files to the service account (read), plus
  Administrators and SYSTEM. `Deploy-ADSync.ps1` does this automatically:
  - the install folder → Administrators/SYSTEM full, service account **modify**
    (it must write logs), inheritance disabled;
  - the `.key` and encrypted config → service account **read-only**, inheritance disabled.
- If you keep an off-host backup of the key/config for DR, store it in your secrets vault —
  it is as sensitive as the API secret itself. (Simplest DR is to just re-provision — §10.)

Verify the resulting ACLs any time with:

```powershell
Get-Acl C:\ADSync\cii-adsync-encryption.key | Format-List
```

---

## 7. Validate with preview mode

Always preview before the first live sync and after any customization change. Preview writes
a local `.jsonl` file and **sends nothing** to CII (it does not even request a token).

```powershell
.\ADSync.ps1 -KeyFilePath .\cii-adsync-encryption.key `
             -ConfigFilePath .\cii-adsync-encrypted-config.json -Preview
```

Open the generated `ad-preview-<timestamp>.jsonl` and check, per user, the `adAttributes`,
`groups`, and `ciiAttributes` sections:
- **`adAttributes`** — are any sensitive/large attributes present that you want excluded?
  Add them via `additionalExcludedAttributes` in your `.psd1`.
- **`ciiAttributes`** — are the classification results (service/admin/executive/external,
  `isAgentic`, `isDeviceAdmin`) what you expect? Tune your `classificationRules`.
- Heed any **large-attribute** or **payload-too-large** warnings.

See [README §Customization](../README.md#customization-and-configuration) for every setting.
When the preview looks right, run one **live** sync manually and confirm the summary:

```powershell
.\ADSync.ps1 -KeyFilePath .\cii-adsync-encryption.key `
             -ConfigFilePath .\cii-adsync-encrypted-config.json `
             -CustomizationFilePath .\ADSync.Config.psd1
```

---

## 8. Deploy the scheduled task

Use the companion installer. Run it **once, elevated (Run as administrator)** on the host.
It is idempotent and supports `-WhatIf`.

**Preview the deployment (changes nothing):**

```powershell
.\Deploy-ADSync.ps1 -ServiceAccount "CORP\svc_cii_adsync" `
    -KeyFilePath    .\cii-adsync-encryption.key `
    -ConfigFilePath .\cii-adsync-encrypted-config.json `
    -CustomizationFilePath .\ADSync.Config.psd1 `
    -WhatIf
```

**Deploy for real** (drop `-WhatIf`; you'll be prompted for the service-account password —
omit the prompt with a gMSA, §4b):

```powershell
.\Deploy-ADSync.ps1 -ServiceAccount "CORP\svc_cii_adsync" `
    -KeyFilePath    .\cii-adsync-encryption.key `
    -ConfigFilePath .\cii-adsync-encrypted-config.json `
    -CustomizationFilePath .\ADSync.Config.psd1
```

What it does (each step idempotent and logged):

1. Verifies Windows, PowerShell 5.1+, and elevation; installs the RSAT `ActiveDirectory`
   module if missing.
2. Creates `C:\ADSync` (override with `-InstallPath`) and a `logs\` subfolder, and copies the
   scripts and provisioned key/config in.
3. Grants the service account **"Log on as a batch job"**.
4. **Hardens the NTFS ACLs** (§6).
5. Registers the `CII-ADSync` Application **event-log source** so the task can raise alerts.
6. Registers a **daily scheduled task** running `Run-ADSync.ps1` as the service account, with
   *Run whether the user is logged on or not*, **not** highest privileges, and these settings:
   *Stop the existing instance* if already running, *Start when available*, a 4-hour time
   limit, and **restart twice at 10-minute intervals** on failure (a task-level retry that
   compensates for the script's lack of internal retries).

Useful parameters: `-InstallPath`, `-TriggerTime "02:00"`, `-TaskName`, `-LogRetentionDays 30`,
`-Gmsa`, `-Credential`. See the script's comment-based help (`Get-Help .\Deploy-ADSync.ps1 -Full`).

**Test it immediately:**

```powershell
Start-ScheduledTask -TaskName "CII-ADSync"
(Get-ScheduledTaskInfo -TaskName "CII-ADSync").LastTaskResult   # expect 0
```

### Manual alternative (no installer)

If you cannot run the installer, create the task by hand per
[README §Windows Task Scheduler](../README.md#windows-task-scheduler). The equivalents you
must not miss: run as the domain service account with **Log on as a batch job**; *Run whether
user is logged on or not*; **not** highest privileges; set **Start in** to the script folder
(this is what makes the relative `-KeyFilePath`/`-ConfigFilePath` and `ADSync.log` resolve —
getting it wrong causes error `2147942402`/`2147942401`); and *Stop the existing instance*.
Point the action at `Run-ADSync.ps1` (not `ADSync.ps1` directly) to keep the log-retention
and alerting behavior in §9.

---

## 9. Reliability, logging & monitoring

`ADSync.ps1` has three operational blind spots. `Run-ADSync.ps1` (the task wrapper the
installer registers) covers all three:

| Gap in `ADSync.ps1` | What the wrapper does |
|---------------------|-----------------------|
| `ADSync.log` is recreated every run — no history. | Archives each run to `logs\ADSync-<timestamp>.log` and prunes past `-LogRetentionDays` (default 30). |
| No alerting on failure. | Writes an **Application event-log** record each run (source `CII-ADSync`). |
| Batch failures don't change the exit code — a run can "succeed" while dropping users. | Scans the run log for partial-failure markers and raises a **Warning** event even on exit 0. Propagates the real exit code to Task Scheduler. |

**Event IDs** (source `CII-ADSync`, log `Application`):

| Event ID | Type | Meaning |
|----------|------|---------|
| 1000 | Information | Sync completed successfully. |
| 1001 | Warning | Completed **with partial failures** — some users may not have been sent; review the archived log. |
| 1002 | Error | Sync failed (non-zero exit). |

**Wire up alerting** on any of these signals (pick what fits your stack — SCOM, Splunk,
Sentinel, or a native Task Scheduler "on an event" trigger emailing your ops inbox):
- Application event log, source `CII-ADSync`, **Event ID 1001 or 1002**.
- Scheduled task **Last Run Result ≠ 0** (`Get-ScheduledTaskInfo`).
- Task **did not run** in the last 24–48h (missed schedule).

> **Why watch 1001 as well as 1002?** A transient CII/network error makes `ADSync.ps1` drop
> only the affected batch and continue — the run still exits 0. Those users recover on the
> next scheduled sync, but you want visibility that it happened.

---

## 10. Operations: change management, DR & rotation

**Version pinning** — record the deployed script version and source revision:
```powershell
.\ADSync.ps1 -version      # prints the script version
```
Keep the exact script package (or git commit) you deployed, so a rebuild is reproducible.

**Customization under change control** — commit your `ADSync.Config.psd1` (it holds **no
secrets**) to your config repo. Re-preview (§7) after any change before it goes live.

**Disaster recovery / rebuild a host:**
1. Stand up a new domain-member server meeting §3.
2. Re-run `Provision.ps1` (re-download the credentials JSON from CII if needed) **or** restore
   the key + encrypted config from your vault.
3. Re-run `Deploy-ADSync.ps1`. Because the encrypted config is only decryptable with its key
   file, re-provisioning on the new host is the clean path.

**Rotate the CII API secret:** rotate it in the CII UI → download the new JSON → re-run
`Provision.ps1` (overwrites the encrypted config) → the next scheduled run picks it up.

**Rotate the service-account password** (standard account): update the password in AD and in
the scheduled task (`Deploy-ADSync.ps1` re-run, or the Task Scheduler UI). **gMSA accounts
rotate automatically — nothing to do.**

**Upgrade the scripts:** replace `ADSync.ps1` / `Provision.ps1` with the new (signed) versions,
re-run `-Preview`, then a live run, before relying on the schedule again.

---

## 11. Troubleshooting

Start with the [README §Troubleshooting](../README.md#troubleshooting) table (log files, preview
mode, connectivity, excessive groups). Deployment-specific pointers:

| Symptom | Likely cause / fix |
|---------|--------------------|
| Task result `2147942402` / `2147942401` (file not found / access denied) | **Start in** / working directory not set to the script folder, or the service account lacks NTFS access. `Deploy-ADSync.ps1` sets both; if you created the task by hand, fix the *Start in* field. |
| Task result `2147943785` or won't run unattended | Service account is missing **Log on as a batch job**, or the stored password is wrong/expired. Re-run the installer. |
| "…is not digitally signed" | Scripts are not yet signed; the task uses `-ExecutionPolicy Bypass`. For a manual session: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. |
| gMSA task fails to start | `Test-ADServiceAccount` on the host must return `True`; the host computer account must be in `PrincipalsAllowedToRetrieveManagedPassword`. |
| Required AD port warning at startup | Open 389/88/9389 (and optionally 3268) from the host to a DC (§3). |
| Run "succeeds" but users missing in CII | Check for a **1001 Warning** event and `"Failed to send request to CII"` / payload-too-large in the archived log. Re-preview to find oversized attributes; exclude them or use `specifiedGroups`/`-NoGroups`. |
| No `CII-ADSync` events appear | The event source was not created (installer not run elevated). Re-run `Deploy-ADSync.ps1` as administrator. |

Logs to check: `logs\ADSync-<timestamp>.log` (archived per run), `Provision.log`
(provisioning), and the Windows **Application** event log (source `CII-ADSync`).

---

## 12. Appendix: reference tables

**Files on the host after deployment** (`C:\ADSync` by default):

| File | Purpose | Sensitivity |
|------|---------|-------------|
| `ADSync.ps1`, `Provision.ps1`, `Run-ADSync.ps1`, `Deploy-ADSync.ps1` | The scripts | Public |
| `*-encryption.key` | AES key for the credentials | **Secret** — read-only for the service account |
| `*-encrypted-config.json` | Encrypted client ID/secret + endpoints | **Secret** — read-only for the service account |
| `ADSync.Config.psd1` | Customization (no secrets) | Internal |
| `ADSync.log` | Latest run log (overwritten each run) | Internal |
| `logs\ADSync-<timestamp>.log` | Archived run logs (retained N days) | Internal |

**Endpoints & ports** — see the table in [§3](#3-prerequisites).

**Key commands**

```powershell
# Provision (one-time, interactive)
.\Provision.ps1 -InputConfigPath .\cii-ad-<integration>-config.json

# Preview (sends nothing)
.\ADSync.ps1 -KeyFilePath .\*.key -ConfigFilePath .\*-encrypted-config.json -Preview

# Deploy the scheduled task (elevated; -WhatIf to preview)
.\Deploy-ADSync.ps1 -ServiceAccount "CORP\svc_cii_adsync" -KeyFilePath .\*.key -ConfigFilePath .\*-encrypted-config.json

# Operate
Start-ScheduledTask   -TaskName "CII-ADSync"
Get-ScheduledTaskInfo -TaskName "CII-ADSync"
Get-EventLog -LogName Application -Source "CII-ADSync" -Newest 10
```

---

*Part of the [cisco-cii-adsync](../README.md) project. Licensed under Apache-2.0.*
