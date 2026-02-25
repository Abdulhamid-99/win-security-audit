# Check Windows Defender / antivirus status
Write-Host "=== Antivirus Status ===" -ForegroundColor Cyan
Get-MpComputerStatus | Select-Object AntivirusEnabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime | Format-List

Write-Host "=== Defender Threat Detection History ===" -ForegroundColor Cyan
Get-MpThreatDetection | Select-Object -First 20 ThreatID,DomainUser,ProcessName,InitialDetectionTime,CleaningAction,Resources | Format-List

Write-Host "=== Defender Exclusions (attackers add these to hide malware) ===" -ForegroundColor Cyan
$prefs = Get-MpPreference -ErrorAction SilentlyContinue
Write-Host "Excluded Paths:"
$prefs.ExclusionPath | ForEach-Object { Write-Host "  $_" }
Write-Host "Excluded Processes:"
$prefs.ExclusionProcess | ForEach-Object { Write-Host "  $_" }
Write-Host "Excluded Extensions:"
$prefs.ExclusionExtension | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== Defender Disable Policy ===" -ForegroundColor Cyan
$pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
Write-Host "DisableAntiSpyware: $($pol.DisableAntiSpyware)"
$rtp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ErrorAction SilentlyContinue
Write-Host "DisableRealtimeMonitoring: $($rtp.DisableRealtimeMonitoring)"

Write-Host "`n=== Third-Party AV Services ===" -ForegroundColor Cyan
Get-WmiObject Win32_Service | Where-Object { $_.DisplayName -match 'Kaspersky|Norton|McAfee|Bitdefender|ESET|Avast|AVG|Malwarebytes|avp' } | Select-Object DisplayName,State,StartMode,PathName | Format-List
