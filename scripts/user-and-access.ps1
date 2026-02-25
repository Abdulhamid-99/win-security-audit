# User accounts, access, and credential exposure checks
Write-Host "=== Local User Accounts ===" -ForegroundColor Cyan
net user

Write-Host "`n=== Administrators Group ===" -ForegroundColor Cyan
net localgroup administrators

Write-Host "`n=== RDP Status ===" -ForegroundColor Cyan
$rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
Write-Host "RDP Deny Connections: $($rdp.fDenyTSConnections) (0=RDP ENABLED, 1=RDP DISABLED)"

Write-Host "`n=== Active Sessions ===" -ForegroundColor Cyan
qwinsta 2>$null

Write-Host "`n=== SSH Keys ===" -ForegroundColor Cyan
Get-ChildItem "$env:USERPROFILE\.ssh" -ErrorAction SilentlyContinue | Select-Object Name,LastWriteTime,Length | Format-Table

Write-Host "`n=== Recent Root Certificates (MITM check) ===" -ForegroundColor Cyan
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.NotBefore -gt (Get-Date).AddMonths(-6) } | Select-Object Subject,NotBefore,NotAfter,Thumbprint | Format-List

Write-Host "`n=== Hosts File ===" -ForegroundColor Cyan
Get-Content "$env:windir\System32\drivers\etc\hosts"

Write-Host "`n=== Recent PowerShell History ===" -ForegroundColor Cyan
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-Object -Last 30
