# Check all persistence mechanisms attackers commonly use
Write-Host "=== Registry Run Keys (HKLM) ===" -ForegroundColor Cyan
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List

Write-Host "`n=== Registry Run Keys (HKCU) ===" -ForegroundColor Cyan
Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List
Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List

Write-Host "`n=== WMI Event Subscriptions (APT persistence) ===" -ForegroundColor Cyan
Write-Host "Event Filters:"
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query | Format-List
Write-Host "Event Consumers:"
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate,ScriptText | Format-List

Write-Host "`n=== Scheduled Tasks (non-Microsoft) ===" -ForegroundColor Cyan
schtasks /query /fo LIST /v | Select-String -Pattern "TaskName|Task To Run|Author|Run As User|Status" | Where-Object { $_ -notmatch 'Microsoft' }

Write-Host "`n=== Services from Non-Standard Locations ===" -ForegroundColor Cyan
Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch 'Windows|Microsoft|System32|SysWOW64|Program Files' } | Select-Object Name,State,StartMode,PathName | Format-Table -AutoSize -Wrap
