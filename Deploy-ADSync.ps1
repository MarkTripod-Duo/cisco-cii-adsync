<#
.SYNOPSIS
    One-time, idempotent installer that turns a host into a production CII ADSync runner.

.DESCRIPTION
    Run this once (elevated) on the chosen domain-member server AFTER you have
    provisioned credentials with Provision.ps1. It automates the manual steps the
    README leaves to the operator so that deployment is repeatable and consistent:

      1. Verifies prerequisites (Windows, PowerShell 5.1+, elevation) and installs
         the RSAT ActiveDirectory PowerShell module if it is missing.
      2. Creates a locked-down install directory (default C:\ADSync) with a \logs
         subfolder and copies the scripts and provisioned key/config into it.
      3. Grants the service account the "Log on as a batch job" right
         (SeBatchLogonRight) via secedit.
      4. Hardens NTFS ACLs: the install folder is restricted to Administrators,
         SYSTEM, and the service account; the encryption key and encrypted config
         are further restricted to read-only for the service account. This closes
         the gap where the key file is otherwise protected only by inherited
         permissions (Provision.ps1 does not set an ACL).
      5. Registers the "CII-ADSync" event-log source so the (non-admin) scheduled
         task can write success/failure events via Run-ADSync.ps1.
      6. Registers a daily Windows Scheduled Task that runs Run-ADSync.ps1 as the
         service account, not with highest privileges, with sensible restart and
         concurrency settings.

    Supports -WhatIf: every mutating action is gated by ShouldProcess, so you can
    preview exactly what the installer would change before committing.

    Standard service accounts and group Managed Service Accounts (gMSA) are both
    supported (-Gmsa). A gMSA is registered with no stored password.

.PARAMETER InstallPath
    Directory the scripts run from. Default: C:\ADSync. Created if missing.

.PARAMETER ServiceAccount
    The account the scheduled task runs as, in DOMAIN\sam form. For a gMSA, use the
    trailing '$' (e.g. CORP\svc-ciiadsync$) and add -Gmsa.

.PARAMETER KeyFilePath
    Path to the provisioned encryption key file. Copied into InstallPath if not
    already there, then locked down.

.PARAMETER ConfigFilePath
    Path to the provisioned encrypted config file. Copied into InstallPath if not
    already there, then locked down.

.PARAMETER CustomizationFilePath
    (Optional) Path to a .psd1 customization file to install and pass to ADSync.

.PARAMETER Gmsa
    Register the task under a group Managed Service Account (no stored password).

.PARAMETER Credential
    (Optional, standard accounts only) Credential for the service account. If
    omitted for a non-gMSA account, you are prompted. Ignored for -Gmsa.

.PARAMETER TriggerTime
    Time of day to run, HH:mm. Default: 02:00.

.PARAMETER TaskName
    Scheduled task name. Default: CII-ADSync.

.PARAMETER LogRetentionDays
    Days of archived logs Run-ADSync.ps1 keeps. Default: 30.

.PARAMETER EventSource
    Application event-log source name. Default: CII-ADSync.

.PARAMETER SourcePath
    Folder to copy ADSync.ps1 / Run-ADSync.ps1 / Provision.ps1 from.
    Default: the folder containing this installer.

.EXAMPLE
    .\Deploy-ADSync.ps1 -ServiceAccount CORP\svc_cii_adsync `
        -KeyFilePath .\cii-adsync-encryption.key `
        -ConfigFilePath .\cii-adsync-encrypted-config.json `
        -CustomizationFilePath .\ADSync.Config.psd1 -WhatIf

    Previews the full deployment without changing anything.

.EXAMPLE
    .\Deploy-ADSync.ps1 -ServiceAccount CORP\svc-ciiadsync$ -Gmsa `
        -KeyFilePath C:\ADSync\cii-adsync-encryption.key `
        -ConfigFilePath C:\ADSync\cii-adsync-encrypted-config.json

    Deploys using a gMSA (no password prompt).

.LINK
    https://docs.oort.io/integrations

.NOTES
    Version: 1.0

    SPDX-License-Identifier: Apache-2.0

    Copyright 2025 Cisco Systems, Inc. and its affiliates

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Service account (DOMAIN\sam; add trailing $ and -Gmsa for a gMSA)")]
    [string]$ServiceAccount,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the provisioned encryption key file")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$KeyFilePath,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the provisioned encrypted config file")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ConfigFilePath,

    [Parameter(Mandatory = $false, HelpMessage = "Path to a .psd1 customization file")]
    [string]$CustomizationFilePath,

    [Parameter(Mandatory = $false, HelpMessage = "Install directory")]
    [string]$InstallPath = "C:\ADSync",

    [Parameter(Mandatory = $false, HelpMessage = "Register under a group Managed Service Account")]
    [switch]$Gmsa,

    [Parameter(Mandatory = $false, HelpMessage = "Service account credential (standard accounts only)")]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = "Daily run time, HH:mm")]
    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$TriggerTime = "02:00",

    [Parameter(Mandatory = $false, HelpMessage = "Scheduled task name")]
    [string]$TaskName = "CII-ADSync",

    [Parameter(Mandatory = $false, HelpMessage = "Days of archived logs to retain")]
    [ValidateRange(0, 3650)]
    [int]$LogRetentionDays = 30,

    [Parameter(Mandatory = $false, HelpMessage = "Application event-log source name")]
    [string]$EventSource = "CII-ADSync",

    [Parameter(Mandatory = $false, HelpMessage = "Folder to copy the scripts from")]
    [string]$SourcePath
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Resolve an account name (DOMAIN\sam or gMSA$) to its SID string.
function Resolve-AccountSid {
    param([string]$Account)
    try {
        return ([System.Security.Principal.NTAccount]$Account).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Could not resolve account '$Account' to a SID. Verify the DOMAIN\name is correct and the domain is reachable. $_"
    }
}

# Grant SeBatchLogonRight ("Log on as a batch job") to a SID via secedit, merging
# with any accounts that already hold the right.
function Grant-BatchLogonRight {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Sid,
        [string]$AccountLabel
    )
    $right = "SeBatchLogonRight"
    $tmpDir = [System.IO.Path]::GetTempPath()
    $exportInf = Join-Path $tmpDir "adsync-secpol-export.inf"
    $importInf = Join-Path $tmpDir "adsync-secpol-import.inf"
    $db        = Join-Path $tmpDir "adsync-secpol.sdb"

    try {
        & secedit /export /areas USER_RIGHTS /cfg $exportInf | Out-Null

        $current = @()
        if (Test-Path $exportInf) {
            $line = Select-String -Path $exportInf -Pattern "^$right\s*=" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($line) {
                $rhs = ($line.Line -split '=', 2)[1].Trim()
                if ($rhs) { $current = $rhs -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
            }
        }

        $token = "*$Sid"
        if ($current -contains $token) {
            Write-Host "    '$AccountLabel' already holds '$right'; no change." -ForegroundColor DarkGray
            return
        }

        if (-not $PSCmdlet.ShouldProcess("$AccountLabel", "Grant '$right' (Log on as a batch job)")) {
            return
        }

        $merged = @($current + $token | Where-Object { $_ } | Select-Object -Unique) -join ','
        $inf = @(
            "[Unicode]"
            "Unicode=yes"
            "[Version]"
            'signature="$CHICAGO$"'
            "Revision=1"
            "[Privilege Rights]"
            "$right = $merged"
        ) -join [Environment]::NewLine
        Set-Content -Path $importInf -Value $inf -Encoding Unicode -Force

        & secedit /configure /db $db /cfg $importInf /areas USER_RIGHTS | Out-Null
        Write-Host "    Granted '$right' to '$AccountLabel'." -ForegroundColor Green
    } finally {
        foreach ($f in @($exportInf, $importInf, $db)) {
            if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
    }
}

# Construct a FileSystemAccessRule (no state change; helper for the ACL functions).
function Get-FsRule {
    param(
        [string]$Identity,
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [switch]$Inherit
    )
    if ($Inherit) {
        $inheritFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    } else {
        $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::None
    }
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identity, $Rights, $inheritFlags,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
}

# Replace a directory's ACL with an explicit, non-inherited rule set.
function Set-HardenedDirectoryAcl {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [string]$Account
    )
    if (-not $PSCmdlet.ShouldProcess($Path, "Harden NTFS ACL (Administrators/SYSTEM full, '$Account' modify, inheritance off)")) {
        return
    }
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)   # protect from inheritance, drop inherited
    foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRule($existing) }
    $acl.AddAccessRule((Get-FsRule -Identity "BUILTIN\Administrators" -Rights FullControl -Inherit))
    $acl.AddAccessRule((Get-FsRule -Identity "NT AUTHORITY\SYSTEM"    -Rights FullControl -Inherit))
    $acl.AddAccessRule((Get-FsRule -Identity $Account                 -Rights Modify      -Inherit))
    Set-Acl -Path $Path -AclObject $acl
    Write-Host "    Hardened directory ACL on $Path" -ForegroundColor Green
}

# Restrict a single secret file to read-only for the service account.
function Set-SecretFileAcl {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [string]$Account
    )
    if (-not $PSCmdlet.ShouldProcess($Path, "Restrict to Administrators/SYSTEM full, '$Account' read-only, inheritance off")) {
        return
    }
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existing in @($acl.Access)) { [void]$acl.RemoveAccessRule($existing) }
    $acl.AddAccessRule((Get-FsRule -Identity "BUILTIN\Administrators" -Rights FullControl))
    $acl.AddAccessRule((Get-FsRule -Identity "NT AUTHORITY\SYSTEM"    -Rights FullControl))
    $acl.AddAccessRule((Get-FsRule -Identity $Account                 -Rights Read))
    Set-Acl -Path $Path -AclObject $acl
    Write-Host "    Locked down secret file $Path" -ForegroundColor Green
}

# Copy a file into the install dir if it is not already there; return the dest path.
function Copy-IntoInstall {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Source, [string]$Dest)
    $leaf = Split-Path $Source -Leaf
    $target = Join-Path $Dest $leaf
    $sourceFull = (Resolve-Path $Source).Path
    if ($sourceFull -ieq $target) { return $target }
    if ($PSCmdlet.ShouldProcess($target, "Copy $leaf into install directory")) {
        Copy-Item -LiteralPath $sourceFull -Destination $target -Force
    }
    return $target
}

# ----------------------------------------------------------------------------
# 0. Preflight
# ----------------------------------------------------------------------------

Write-Step "Checking prerequisites"

$runningOnWindows = $true
if ($PSVersionTable.PSVersion.Major -ge 6) { $runningOnWindows = [bool]$IsWindows }
if (-not $runningOnWindows) {
    throw "Deploy-ADSync.ps1 must be run on a Windows Server domain member (Windows PowerShell 5.1)."
}
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw "PowerShell 5.1 or later is required. Detected $($PSVersionTable.PSVersion)."
}

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This installer must be run from an elevated (Run as administrator) PowerShell session."
}

if (-not $SourcePath) { $SourcePath = $PSScriptRoot }
foreach ($required in @("ADSync.ps1", "Run-ADSync.ps1")) {
    if (-not (Test-Path (Join-Path $SourcePath $required))) {
        throw "Required script '$required' not found in SourcePath '$SourcePath'."
    }
}
if ($CustomizationFilePath -and -not (Test-Path $CustomizationFilePath -PathType Leaf)) {
    throw "CustomizationFilePath '$CustomizationFilePath' does not exist."
}

$accountSid = Resolve-AccountSid -Account $ServiceAccount
Write-Host "    Service account '$ServiceAccount' resolved to SID $accountSid" -ForegroundColor DarkGray

# ----------------------------------------------------------------------------
# 1. RSAT ActiveDirectory module
# ----------------------------------------------------------------------------

Write-Step "Ensuring the ActiveDirectory PowerShell module is available"
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host "    ActiveDirectory module already present." -ForegroundColor DarkGray
} elseif ($PSCmdlet.ShouldProcess("RSAT ActiveDirectory PowerShell module", "Install")) {
    $installed = $false
    if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
        # Server SKU path; fall through to the capability path if this fails.
        try { Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop | Out-Null; $installed = $true }
        catch { Write-Verbose "Install-WindowsFeature failed: $_" }
    }
    if (-not $installed -and (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue)) {
        # Client/Server 2019+ Features-on-Demand path.
        try {
            Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop | Out-Null
            $installed = $true
        } catch { Write-Verbose "Add-WindowsCapability failed: $_" }
    }
    if (-not $installed) {
        throw "Could not install the ActiveDirectory module automatically. Install RSAT-AD-PowerShell manually and re-run."
    }
    Write-Host "    ActiveDirectory module installed." -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# 2. Install directory + copy files
# ----------------------------------------------------------------------------

Write-Step "Preparing install directory: $InstallPath"
if (-not (Test-Path $InstallPath)) {
    if ($PSCmdlet.ShouldProcess($InstallPath, "Create install directory")) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
}
$logsDir = Join-Path $InstallPath "logs"
if (-not (Test-Path $logsDir)) {
    if ($PSCmdlet.ShouldProcess($logsDir, "Create logs subdirectory")) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }
}

Write-Step "Copying scripts and provisioned files into $InstallPath"
foreach ($script in @("ADSync.ps1", "Run-ADSync.ps1", "Provision.ps1")) {
    $src = Join-Path $SourcePath $script
    if (Test-Path $src) { [void](Copy-IntoInstall -Source $src -Dest $InstallPath) }
}
$destKey    = Copy-IntoInstall -Source $KeyFilePath    -Dest $InstallPath
$destConfig = Copy-IntoInstall -Source $ConfigFilePath -Dest $InstallPath
$destCustomization = $null
if ($CustomizationFilePath) {
    $destCustomization = Copy-IntoInstall -Source $CustomizationFilePath -Dest $InstallPath
}

# ----------------------------------------------------------------------------
# 3. Log on as a batch job
# ----------------------------------------------------------------------------

Write-Step "Granting 'Log on as a batch job' to $ServiceAccount"
Grant-BatchLogonRight -Sid $accountSid -AccountLabel $ServiceAccount

# ----------------------------------------------------------------------------
# 4. NTFS ACL hardening
# ----------------------------------------------------------------------------

Write-Step "Hardening NTFS permissions"
Set-HardenedDirectoryAcl -Path $InstallPath -Account $ServiceAccount
# The key and encrypted config only need to be READ by the service account.
Set-SecretFileAcl -Path $destKey    -Account $ServiceAccount
Set-SecretFileAcl -Path $destConfig -Account $ServiceAccount

# ----------------------------------------------------------------------------
# 5. Event-log source
# ----------------------------------------------------------------------------

Write-Step "Ensuring the '$EventSource' Application event-log source exists"
$sourceExists = $false
try { $sourceExists = [System.Diagnostics.EventLog]::SourceExists($EventSource) }
catch { Write-Verbose "SourceExists check failed: $_" }
if ($sourceExists) {
    Write-Host "    Event source already registered." -ForegroundColor DarkGray
} elseif ($PSCmdlet.ShouldProcess($EventSource, "Create Application event-log source")) {
    New-EventLog -LogName Application -Source $EventSource
    Write-Host "    Event source created." -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# 6. Scheduled task
# ----------------------------------------------------------------------------

Write-Step "Registering scheduled task '$TaskName'"

$powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$runScript = Join-Path $InstallPath "Run-ADSync.ps1"

$argParts = @(
    "-NoProfile"
    "-ExecutionPolicy Bypass"
    "-File `"$runScript`""
    "-KeyFilePath `"$destKey`""
    "-ConfigFilePath `"$destConfig`""
    "-LogRetentionDays $LogRetentionDays"
    "-EventSource `"$EventSource`""
)
if ($destCustomization) { $argParts += "-CustomizationFilePath `"$destCustomization`"" }
$taskArguments = $argParts -join ' '

$action   = New-ScheduledTaskAction -Execute $powershellExe -Argument $taskArguments -WorkingDirectory $InstallPath
$trigger  = New-ScheduledTaskTrigger -Daily -At $TriggerTime
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances StopExisting `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 10)

if ($PSCmdlet.ShouldProcess($TaskName, "Register daily scheduled task at $TriggerTime as $ServiceAccount")) {
    if ($Gmsa) {
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Limited
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $taskPrincipal -Force | Out-Null
    } else {
        if (-not $Credential) {
            $Credential = Get-Credential -UserName $ServiceAccount -Message "Password for the CII ADSync service account ($ServiceAccount)"
        }
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -User $ServiceAccount `
            -Password $Credential.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null
    }
    Write-Host "    Registered task '$TaskName'." -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# Summary / next steps
# ----------------------------------------------------------------------------

Write-Host ""
Write-Step "Deployment summary"
Write-Host "    Install dir      : $InstallPath"
Write-Host "    Service account  : $ServiceAccount$(if ($Gmsa) { ' (gMSA)' })"
Write-Host "    Key file         : $destKey"
Write-Host "    Config file      : $destConfig"
if ($destCustomization) { Write-Host "    Customization    : $destCustomization" }
Write-Host "    Task             : $TaskName (daily at $TriggerTime)"
Write-Host "    Log archives     : $logsDir (retain $LogRetentionDays days)"
Write-Host "    Event source     : $EventSource (Application log)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. If you have not provisioned yet, run Provision.ps1 first, then re-run this installer."
Write-Host "  2. Validate collection without sending:  .\ADSync.ps1 -KeyFilePath `"$destKey`" -ConfigFilePath `"$destConfig`" -Preview"
Write-Host "  3. Test the scheduled task now:          Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "  4. Check the result:                     (Get-ScheduledTaskInfo -TaskName '$TaskName').LastTaskResult   # expect 0"
Write-Host "  5. Review the archived log in:           $logsDir"
Write-Host ""
Write-Host "Deployment complete." -ForegroundColor Green
