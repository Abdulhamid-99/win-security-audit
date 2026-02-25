# Network connection audit - maps all connections to processes
Write-Host "=== Listening Ports ===" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort    = $_.LocalPort
        PID          = $_.OwningProcess
        Process      = $proc.ProcessName
        Path         = $proc.Path
    }
} | Sort-Object LocalPort | Format-Table -AutoSize -Wrap

Write-Host "`n=== External Established Connections ===" -ForegroundColor Cyan
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' } | Sort-Object RemoteAddress -Unique | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        PID           = $_.OwningProcess
        Process       = $proc.ProcessName
        Path          = $proc.Path
    }
} | Format-Table -AutoSize -Wrap

Write-Host "`n=== Firewall Status ===" -ForegroundColor Cyan
Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table

Write-Host "=== SMB Configuration ===" -ForegroundColor Cyan
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol | Format-List

Write-Host "=== Network Profile ===" -ForegroundColor Cyan
Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,NetworkCategory | Format-Table

Write-Host "=== Proxy Settings ===" -ForegroundColor Cyan
$proxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
Write-Host "Proxy Enabled: $($proxy.ProxyEnable)"
Write-Host "Proxy Server: $($proxy.ProxyServer)"

Write-Host "`n=== Network Shares ===" -ForegroundColor Cyan
net share
