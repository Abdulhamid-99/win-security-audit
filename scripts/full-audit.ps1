# Full Security Audit - runs all checks and saves report
# Usage: powershell -ExecutionPolicy Bypass -File full-audit.ps1
param(
    [string]$OutputDir = (Split-Path -Parent $PSScriptRoot)
)

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportFile = Join-Path $OutputDir "reports\security-report_$timestamp.txt"
$reportsDir = Join-Path $OutputDir "reports"

if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null }

Write-Host "Running full security audit..." -ForegroundColor Green
Write-Host "Report will be saved to: $reportFile" -ForegroundColor Yellow

$scriptDir = $PSScriptRoot

& {
    Write-Output "=============================================="
    Write-Output "  SECURITY AUDIT REPORT"
    Write-Output "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output "  Machine: $env:COMPUTERNAME"
    Write-Output "  User: $env:USERNAME"
    Write-Output "=============================================="
    Write-Output ""

    Write-Output ">>> DEFENDER / ANTIVIRUS STATUS"
    Write-Output "----------------------------------------------"
    & "$scriptDir\defender-status.ps1" 2>&1

    Write-Output "`n>>> NETWORK AUDIT"
    Write-Output "----------------------------------------------"
    & "$scriptDir\network-audit.ps1" 2>&1

    Write-Output "`n>>> PERSISTENCE MECHANISMS"
    Write-Output "----------------------------------------------"
    & "$scriptDir\persistence-check.ps1" 2>&1

    Write-Output "`n>>> USER & ACCESS AUDIT"
    Write-Output "----------------------------------------------"
    & "$scriptDir\user-and-access.ps1" 2>&1

    Write-Output "`n>>> PROCESS AUDIT"
    Write-Output "----------------------------------------------"
    & "$scriptDir\process-audit.ps1" 2>&1
} *>&1 | Tee-Object -FilePath $reportFile

Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
