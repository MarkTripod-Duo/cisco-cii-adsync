<#
.SYNOPSIS
    Production task wrapper for ADSync.ps1.

.DESCRIPTION
    Thin, dependency-free wrapper intended to be the target of the Windows Task
    Scheduler action created by Deploy-ADSync.ps1. It exists to close three
    operational gaps in ADSync.ps1 that matter for unattended, scheduled runs:

      1. Log retention - ADSync.ps1 recreates ".\ADSync.log" with -Force on every
         run, so only the most recent run is ever retained. This wrapper archives
         each run's log to ".\logs\ADSync-<timestamp>.log" and prunes archives
         older than -LogRetentionDays.

      2. Failure signalling - ADSync.ps1 has no alerting. This wrapper writes a
         success/warning/failure record to the Windows Application event log
         (source "CII-ADSync") so enterprise monitoring (SCOM, Splunk, Sentinel,
         Task Scheduler "on an event" email, etc.) can alert on it.

      3. Meaningful exit codes - individual SCIM batch failures do not change the
         ADSync.ps1 exit code, so a run can "succeed" (exit 0) while silently
         dropping users. This wrapper scans the run's log for known partial-failure
         markers and downgrades an exit-0 run to a WARNING event when found. The
         underlying ADSync exit code is always propagated to Task Scheduler.

    ADSync.ps1 is invoked with the call operator; its internal "exit N" returns
    control here (setting $LASTEXITCODE) rather than terminating this wrapper, and
    the archive/alert steps run inside a finally block so they execute regardless
    of how the run ends.

.PARAMETER KeyFilePath
    Path to the encryption key file. Passed through to ADSync.ps1.

.PARAMETER ConfigFilePath
    Path to the encrypted configuration file. Passed through to ADSync.ps1.

.PARAMETER CustomizationFilePath
    (Optional) Path to a .psd1 customization file. Passed through to ADSync.ps1.

.PARAMETER BaseDN
    (Optional) Base DN to limit the sync. Passed through to ADSync.ps1.

.PARAMETER NoGroups
    (Optional) Skip uploading user groups. Passed through to ADSync.ps1.

.PARAMETER ScriptPath
    (Optional) Path to ADSync.ps1. Defaults to ADSync.ps1 next to this wrapper.

.PARAMETER LogRetentionDays
    (Optional) Days of archived ADSync logs to keep in .\logs. Default: 30.
    Set to 0 to keep all archives (no pruning).

.PARAMETER EventSource
    (Optional) Application event-log source name. Default: "CII-ADSync".
    The source is created by Deploy-ADSync.ps1 (which runs elevated); if it is
    missing this wrapper skips event logging rather than failing.

.EXAMPLE
    .\Run-ADSync.ps1 -KeyFilePath .\cii-adsync-encryption.key -ConfigFilePath .\cii-adsync-encrypted-config.json -CustomizationFilePath .\ADSync.Config.psd1

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

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'EventSource',
    Justification = 'Read by Test-EventSource/Write-RunEvent through script scope.')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the encryption key file")]
    [string]$KeyFilePath,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the encrypted configuration file")]
    [string]$ConfigFilePath,

    [Parameter(Mandatory = $false, HelpMessage = "Path to the customization .psd1 file")]
    [string]$CustomizationFilePath,

    [Parameter(Mandatory = $false, HelpMessage = "Base DN to limit the sync")]
    [string]$BaseDN,

    [Parameter(Mandatory = $false, HelpMessage = "Skip uploading user groups")]
    [switch]$NoGroups,

    [Parameter(Mandatory = $false, HelpMessage = "Path to ADSync.ps1 (defaults to alongside this wrapper)")]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false, HelpMessage = "Days of archived logs to retain (0 = keep all)")]
    [ValidateRange(0, 3650)]
    [int]$LogRetentionDays = 30,

    [Parameter(Mandatory = $false, HelpMessage = "Application event-log source name")]
    [string]$EventSource = "CII-ADSync"
)

# Event IDs used for the Application log record.
$EVENT_ID_SUCCESS = 1000
$EVENT_ID_WARNING = 1001
$EVENT_ID_FAILURE = 1002

# Log markers that indicate a partial failure even when ADSync exits 0.
# (See ADSync.ps1 Send-ScimBulkRequest / Show-AttributeSizeSummary / summary block.)
$partialFailureMarkers = @(
    "Failed to send request to CII"
    "payload too large"
    "Payload Too Large"
    "Users Processed: 0"
)

# Resolve the install directory (this wrapper's own folder) and run from there so
# ADSync.ps1's relative ".\ADSync.log" and preview files land in a known location.
$installDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($installDir)) {
    $installDir = (Get-Location).Path
}
Set-Location -LiteralPath $installDir

# Default the ADSync.ps1 location to alongside this wrapper.
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Join-Path $installDir "ADSync.ps1"
}
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    Write-Error "ADSync script not found at: $ScriptPath"
    exit 1
}

$logsDir = Join-Path $installDir "logs"
if (-not (Test-Path -LiteralPath $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}
$runLog = Join-Path $installDir "ADSync.log"

# Returns $true if the event-log source is registered and usable.
function Test-EventSource {
    param([string]$Source)
    try {
        return [System.Diagnostics.EventLog]::SourceExists($Source)
    } catch {
        return $false
    }
}

# Writes a record to the Application event log if the source exists; otherwise warns.
function Write-RunEvent {
    param(
        [int]$EventId,
        [ValidateSet("Information", "Warning", "Error")]
        [string]$EntryType,
        [string]$Message
    )
    if (Test-EventSource -Source $EventSource) {
        try {
            Write-EventLog -LogName Application -Source $EventSource `
                -EventId $EventId -EntryType $EntryType -Message $Message
        } catch {
            Write-Warning "Could not write to the Application event log: $_"
        }
    } else {
        Write-Warning "Event source '$EventSource' is not registered; skipping event log. Run Deploy-ADSync.ps1 (elevated) to create it."
    }
}

# Build the ADSync.ps1 parameter set. Only forward the switches/values supplied.
$adsyncParams = @{
    KeyFilePath    = $KeyFilePath
    ConfigFilePath = $ConfigFilePath
}
if (-not [string]::IsNullOrWhiteSpace($CustomizationFilePath)) { $adsyncParams.CustomizationFilePath = $CustomizationFilePath }
if (-not [string]::IsNullOrWhiteSpace($BaseDN))                { $adsyncParams.BaseDN = $BaseDN }
if ($NoGroups)                                                 { $adsyncParams.NoGroups = $true }

$startTime = Get-Date
$exitCode = 0
$runError = $null

try {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting ADSync via $ScriptPath"
    & $ScriptPath @adsyncParams
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }
} catch {
    $exitCode = 1
    $runError = $_
    Write-Warning "ADSync run threw a terminating error: $_"
} finally {
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $stamp = $startTime.ToString('yyyyMMdd-HHmmss')

    # --- Archive this run's log so it is not lost to the next run's -Force truncate ---
    $archivedPath = $null
    if (Test-Path -LiteralPath $runLog) {
        try {
            $archivedPath = Join-Path $logsDir "ADSync-$stamp.log"
            Copy-Item -LiteralPath $runLog -Destination $archivedPath -Force
        } catch {
            Write-Warning "Failed to archive run log: $_"
        }
    } else {
        Write-Warning "No ADSync.log was produced for this run."
    }

    # --- Prune archives older than the retention window ---
    if ($LogRetentionDays -gt 0) {
        try {
            $cutoff = (Get-Date).AddDays(-$LogRetentionDays)
            Get-ChildItem -LiteralPath $logsDir -Filter "ADSync-*.log" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Failed to prune old log archives: $_"
        }
    }

    # --- Detect partial failure (exit 0 but the log shows dropped/oversized users) ---
    $partialFailure = $false
    if ($exitCode -eq 0 -and $archivedPath -and (Test-Path -LiteralPath $archivedPath)) {
        try {
            $logText = Get-Content -LiteralPath $archivedPath -Raw -ErrorAction SilentlyContinue
            foreach ($marker in $partialFailureMarkers) {
                if ($logText -and $logText -match [regex]::Escape($marker)) {
                    $partialFailure = $true
                    break
                }
            }
        } catch {
            Write-Warning "Could not scan the run log for partial-failure markers: $_"
        }
    }

    # --- Emit a single event summarising the run ---
    $durationText = "{0:hh\:mm\:ss}" -f $duration
    $summary = @(
        "CII ADSync run finished."
        "Exit code : $exitCode"
        "Duration  : $durationText"
        "Log       : $archivedPath"
        "Install   : $installDir"
    )
    if ($runError) { $summary += "Error     : $($runError.Exception.Message)" }

    if ($exitCode -ne 0) {
        $summary = ,"ADSync FAILED." + $summary
        Write-RunEvent -EventId $EVENT_ID_FAILURE -EntryType Error -Message ($summary -join [Environment]::NewLine)
    } elseif ($partialFailure) {
        $summary = ,"ADSync completed with partial failures (some users may not have been sent). Review the archived log." + $summary
        Write-RunEvent -EventId $EVENT_ID_WARNING -EntryType Warning -Message ($summary -join [Environment]::NewLine)
    } else {
        $summary = ,"ADSync completed successfully." + $summary
        Write-RunEvent -EventId $EVENT_ID_SUCCESS -EntryType Information -Message ($summary -join [Environment]::NewLine)
    }

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ADSync wrapper finished. Exit code: $exitCode (duration $durationText)"
}

exit $exitCode
