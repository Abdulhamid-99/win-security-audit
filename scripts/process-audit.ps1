# Audit running processes for suspicious activity
Write-Host "=== Processes from Non-Standard Locations ===" -ForegroundColor Cyan
Get-Process | Where-Object {$_.Path -and $_.Path -notmatch 'Windows|Microsoft|System32|Program Files'} | Select-Object Id,ProcessName,Path | Sort-Object ProcessName | Format-Table -AutoSize -Wrap

Write-Host "`n=== OS and Update Status ===" -ForegroundColor Cyan
Get-ComputerInfo | Select-Object OsName,OsVersion,OsBuildNumber,OsArchitecture,WindowsVersion | Format-List
$AU = (New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction SilentlyContinue)
$AU.Results | Format-List
