#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Endpoint Security Audit — single-command comprehensive scan.
.DESCRIPTION
    Checks antivirus, network, persistence, user access, and process integrity.
    Saves a timestamped report to the reports/ directory.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File full-audit.ps1
    powershell -ExecutionPolicy Bypass -File full-audit.ps1 -SkipReport
#>
param(
    [switch]$SkipReport
)

$ErrorActionPreference = 'SilentlyContinue'
$scriptDir = $PSScriptRoot
$rootDir   = Split-Path -Parent $scriptDir
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportDir = Join-Path $rootDir "reports"
$reportFile = Join-Path $reportDir "security-report_$timestamp.txt"

if (-not $SkipReport -and -not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

function Write-Section($title) {
    Write-Output ""
    Write-Output ("=" * 60)
    Write-Output "  $title"
    Write-Output ("=" * 60)
}

function Write-Check($name) {
    Write-Output ""
    Write-Output "--- $name ---"
}

# ── Collect all output ──────────────────────────────────────
$audit = & {

    Write-Output "WINDOWS ENDPOINT SECURITY AUDIT"
    Write-Output "Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "Machine  : $env:COMPUTERNAME"
    Write-Output "User     : $env:USERNAME"
    Write-Output "OS       : $((Get-CimInstance Win32_OperatingSystem).Caption) Build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

    # ════════════════════════════════════════════════════════
    Write-Section "1. ANTIVIRUS / ENDPOINT PROTECTION"
    # ════════════════════════════════════════════════════════

    Write-Check "Windows Defender Status"
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        Write-Output "  Antivirus Enabled        : $($mp.AntivirusEnabled)"
        Write-Output "  Real-Time Protection     : $($mp.RealTimeProtectionEnabled)"
        Write-Output "  Behavior Monitor         : $($mp.BehaviorMonitorEnabled)"
        Write-Output "  IOAV Protection          : $($mp.IoavProtectionEnabled)"
        Write-Output "  Signature Last Updated   : $($mp.AntivirusSignatureLastUpdated)"
        Write-Output "  Last Quick Scan          : $($mp.QuickScanEndTime)"
        Write-Output "  Last Full Scan           : $($mp.FullScanEndTime)"
    } else {
        Write-Output "  [!] Could not query Defender (may be disabled by third-party AV)"
    }

    Write-Check "Defender Exclusions"
    $prefs = Get-MpPreference -ErrorAction SilentlyContinue
    if ($prefs) {
        $exPaths = $prefs.ExclusionPath | Where-Object { $_ }
        $exProcs = $prefs.ExclusionProcess | Where-Object { $_ }
        $exExts  = $prefs.ExclusionExtension | Where-Object { $_ }
        $hasExclusions = $false
        if ($exPaths) { $hasExclusions = $true; $exPaths | ForEach-Object { Write-Output "  [!] Excluded Path: $_" } }
        if ($exProcs) { $hasExclusions = $true; $exProcs | ForEach-Object { Write-Output "  [!] Excluded Process: $_" } }
        if ($exExts)  { $hasExclusions = $true; $exExts  | ForEach-Object { Write-Output "  [!] Excluded Extension: $_" } }
        if (-not $hasExclusions) { Write-Output "  No exclusions configured (clean)" }
    }

    Write-Check "Defender Group Policy Override"
    $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
    $rtp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ErrorAction SilentlyContinue
    if ($pol.DisableAntiSpyware -eq 1) { Write-Output "  [!!] DisableAntiSpyware = 1 (FORCED OFF BY POLICY)" }
    elseif ($rtp.DisableRealtimeMonitoring -eq 1) { Write-Output "  [!!] DisableRealtimeMonitoring = 1 (FORCED OFF BY POLICY)" }
    else { Write-Output "  No disable policies set (clean)" }

    Write-Check "Third-Party Antivirus"
    $avServices = Get-WmiObject Win32_Service | Where-Object { $_.DisplayName -match 'Kaspersky|Norton|McAfee|Bitdefender|ESET|Avast|AVG|Malwarebytes|Sophos|Trend Micro|CrowdStrike|SentinelOne|Cylance|Webroot' }
    if ($avServices) {
        foreach ($svc in $avServices) {
            Write-Output "  $($svc.DisplayName) [$($svc.State)] Start:$($svc.StartMode)"
        }
    } else {
        Write-Output "  No third-party AV detected"
    }

    # ════════════════════════════════════════════════════════
    Write-Section "2. NETWORK SECURITY"
    # ════════════════════════════════════════════════════════

    Write-Check "Firewall Status"
    Get-NetFirewallProfile | ForEach-Object {
        $status = if ($_.Enabled) { "ON" } else { "[!!] OFF" }
        Write-Output "  $($_.Name): $status"
    }

    Write-Check "SMB Configuration"
    $smb = Get-SmbServerConfiguration
    if ($smb.EnableSMB1Protocol) { Write-Output "  [!!] SMBv1 ENABLED (vulnerable to EternalBlue/WannaCry)" }
    else { Write-Output "  SMBv1: Disabled (secure)" }
    Write-Output "  SMBv2: $($smb.EnableSMB2Protocol)"

    Write-Check "Network Profile"
    Get-NetConnectionProfile | ForEach-Object {
        Write-Output "  $($_.InterfaceAlias): $($_.NetworkCategory) ($($_.Name))"
    }

    Write-Check "Proxy Settings (MITM indicator)"
    $proxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($proxy.ProxyEnable -eq 1) {
        Write-Output "  [!] Proxy ENABLED: $($proxy.ProxyServer)"
    } else {
        Write-Output "  No proxy configured (clean)"
    }

    Write-Check "Network Shares"
    net share 2>&1 | ForEach-Object { Write-Output "  $_" }

    Write-Check "Listening Ports"
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        Write-Output "  $($_.LocalAddress):$($_.LocalPort) [$($proc.ProcessName)]"
    }

    Write-Check "External Connections (non-loopback)"
    $extConns = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' }
    $extConns | Sort-Object RemoteAddress -Unique | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        Write-Output "  $($_.RemoteAddress):$($_.RemotePort) [$($proc.ProcessName)]"
    }

    # ════════════════════════════════════════════════════════
    Write-Section "3. PERSISTENCE MECHANISMS"
    # ════════════════════════════════════════════════════════

    Write-Check "Registry Run Keys (HKLM)"
    $hklmRun = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    $hklmRun.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-Output "  $($_.Name) = $($_.Value)"
    }

    Write-Check "Registry Run Keys (HKCU)"
    $hkcuRun = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    $hkcuRun.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-Output "  $($_.Name) = $($_.Value)"
    }

    Write-Check "WMI Event Subscriptions (APT persistence)"
    $filters = Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $consumers = Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    $malWmi = $filters | Where-Object { $_.Name -notmatch 'SCM Event' }
    if ($malWmi) {
        foreach ($f in $malWmi) { Write-Output "  [!!] Filter: $($f.Name) Query: $($f.Query)" }
    } else {
        Write-Output "  Only default SCM subscription found (clean)"
    }

    Write-Check "Scheduled Tasks (non-Microsoft)"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Author -and $_.Author -notmatch 'Microsoft' -and $_.State -ne 'Disabled' }
    foreach ($t in $tasks) {
        $actions = ($t.Actions | ForEach-Object { $_.Execute }) -join "; "
        Write-Output "  $($t.TaskName) | Author: $($t.Author) | Run: $actions"
    }

    Write-Check "Services from Non-Standard Locations"
    Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch 'Windows|Microsoft|System32|SysWOW64|Program Files' -and $_.State -eq 'Running' } | ForEach-Object {
        Write-Output "  $($_.Name) [$($_.State)] $($_.PathName)"
    }

    # ════════════════════════════════════════════════════════
    Write-Section "4. USER ACCOUNTS & ACCESS"
    # ════════════════════════════════════════════════════════

    Write-Check "Local User Accounts"
    Get-LocalUser | ForEach-Object {
        $status = if ($_.Enabled) { "Enabled" } else { "Disabled" }
        Write-Output "  $($_.Name) [$status] Last Logon: $($_.LastLogon)"
    }

    Write-Check "Administrators Group"
    $admins = net localgroup administrators 2>&1
    $admins | ForEach-Object { Write-Output "  $_" }

    Write-Check "RDP Status"
    $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdp.fDenyTSConnections -eq 0) { Write-Output "  [!] RDP is ENABLED" }
    else { Write-Output "  RDP is DISABLED (secure)" }

    Write-Check "Active Sessions"
    qwinsta 2>&1 | ForEach-Object { Write-Output "  $_" }

    Write-Check "SSH Keys"
    $sshDir = Join-Path $env:USERPROFILE ".ssh"
    if (Test-Path $sshDir) {
        Get-ChildItem $sshDir | ForEach-Object {
            Write-Output "  $($_.Name)  ($($_.Length) bytes, modified $($_.LastWriteTime.ToString('yyyy-MM-dd')))"
        }
    } else {
        Write-Output "  No .ssh directory found"
    }

    Write-Check "Recently Added Root Certificates (last 6 months)"
    $recentCerts = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.NotBefore -gt (Get-Date).AddMonths(-6) }
    if ($recentCerts) {
        foreach ($cert in $recentCerts) {
            Write-Output "  [!] $($cert.Subject) (added $($cert.NotBefore.ToString('yyyy-MM-dd')))"
        }
    } else {
        Write-Output "  No recently added root certificates (clean)"
    }

    Write-Check "Hosts File"
    $hostsContent = Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -and $_ -notmatch '^\s*#' }
    if ($hostsContent) {
        $hostsContent | ForEach-Object { Write-Output "  $_" }
    } else {
        Write-Output "  Default (no custom entries)"
    }

    # ════════════════════════════════════════════════════════
    Write-Section "5. PROCESS INTEGRITY"
    # ════════════════════════════════════════════════════════

    Write-Check "Processes from Non-Standard Locations"
    Get-Process | Where-Object { $_.Path -and $_.Path -notmatch 'Windows|Microsoft|System32|Program Files' } | Sort-Object ProcessName -Unique | ForEach-Object {
        Write-Output "  $($_.ProcessName) : $($_.Path)"
    }

    Write-Check "OS Info and Patch Level"
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Output "  $($os.Caption) Build $($os.BuildNumber)"
    Write-Output "  Last Boot: $($os.LastBootUpTime)"
    $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hotfix) {
        Write-Output "  Latest Patch: $($hotfix.HotFixID) installed $($hotfix.InstalledOn.ToString('yyyy-MM-dd'))"
    }

    # ════════════════════════════════════════════════════════
    Write-Section "AUDIT COMPLETE"
    # ════════════════════════════════════════════════════════
    Write-Output "  Finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

# ── Output ──────────────────────────────────────────────────
if ($SkipReport) {
    $audit
} else {
    $audit | Tee-Object -FilePath $reportFile
    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
}
