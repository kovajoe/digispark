<#
.SYNOPSIS
  Read-only scan to collect common indicators of suspicious activity on a Windows host.

.DESCRIPTION
  This script gathers:
    - Processes whose command lines include suspicious PowerShell / download / execution patterns
    - Scheduled Tasks outside the Microsoft folder
    - Autorun registry entries (HKLM / HKCU Run)
    - Services with suspicious paths (e.g., running from Temp or user AppData)
    - Established external network connections and associated processes
    - PowerShell event log entries (last 7 days) that include suspicious patterns

  The script only reads system state and writes a report to an output folder.
  Recommended to run as Administrator to capture the fullest set of information.

.PARAMETER OutputRoot
  Root folder where scan results will be written. Default: C:\SuspiciousScan

.EXAMPLE
  .\Detect-SuspiciousActivity.ps1
  .\Detect-SuspiciousActivity.ps1 -OutputRoot "C:\Scans"
#>

param(
    [string]$OutputRoot = "C:\SuspiciousScan"
)

function Get-Timestamp { Get-Date -Format "yyyyMMdd_HHmmss" }

# Prepare output directory
$ts = Get-Timestamp
$OutDir = Join-Path -Path $OutputRoot -ChildPath "Scan_$ts"
New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

# Suspicious indicator strings (case-insensitive searches)
$suspIndicators = @(
    "IEX", "Invoke-Expression", "Invoke-WebRequest", "iwr", "DownloadString",
    "-EncodedCommand", "-enc", "-windowstyle hidden", "FromBase64String", "Start-Process -WindowStyle Hidden",
    "DownloadFile", "WebClient", "System.Net.WebClient", "New-Object System.Net.WebClient"
)

Write-Output "Starting read-only suspicious activity scan..."
Write-Output "Results will be saved to: $OutDir`n"

# 1) Running processes with suspicious command lines
Write-Output "Scanning running processes for suspicious command lines..."
try {
    $procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ParentProcessId
    $exeFilter = 'powershell.exe|pwsh.exe|cmd.exe|wscript.exe|cscript.exe|rundll32.exe|regsvr32.exe'
    $procSuspicious = @()
    foreach ($p in $procs) {
        if (-not $p.CommandLine) { continue }
        if ($p.Name -imatch $exeFilter) {
            foreach ($ind in $suspIndicators) {
                if ($p.CommandLine -imatch [regex]::Escape($ind)) {
                    $procSuspicious += $p
                    break
                }
            }
        }
    }
    $procSuspicious | Sort-Object Name, ProcessId | Export-Csv -Path (Join-Path $OutDir "processes_suspicious.csv") -NoTypeInformation -Encoding UTF8
    $procSuspicious | Format-Table -AutoSize | Out-String | Set-Content (Join-Path $OutDir "processes_suspicious.txt")
} catch {
    "Error enumerating processes: $_" | Out-File (Join-Path $OutDir "processes_error.txt")
}

# 2) Scheduled Tasks outside the Microsoft folder
Write-Output "Scanning scheduled tasks (non-Microsoft)..."
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | Select-Object TaskName, TaskPath, State, Author
    $tasks | Export-Csv -Path (Join-Path $OutDir "scheduledtasks_nonmicrosoft.csv") -NoTypeInformation -Encoding UTF8
    $tasks | Out-String | Set-Content (Join-Path $OutDir "scheduledtasks_nonmicrosoft.txt")
} catch {
    "Cannot enumerate scheduled tasks: $_" | Out-File (Join-Path $OutDir "scheduledtasks_error.txt")
}

# 3) Autorun registry keys (HKLM/HKCU Run)
Write-Output "Collecting autorun registry entries (Run keys)..."
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
$autoruns = @()
foreach ($k in $runKeys) {
    try {
        $items = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($items) {
            $props = $items.PSObject.Properties | Where-Object { $_.Name -notin "PSPath","PSParentPath","PSChildName","PSDrive","PSProvider" }
            foreach ($p in $props) {
                $autoruns += [PSCustomObject]@{
                    Key = $k
                    Name = $p.Name
                    Value = $p.Value
                }
            }
        }
    } catch { }
}
$autoruns | Export-Csv -Path (Join-Path $OutDir "autoruns.csv") -NoTypeInformation -Encoding UTF8
$autoruns | Out-String | Set-Content (Join-Path $OutDir "autoruns.txt")

# 4) Services with suspicious paths or unusual start locations
Write-Output "Scanning services for suspicious paths..."
try {
    $svcs = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName
    $svcSuspicious = $svcs | Where-Object {
        ($_.PathName -and ($_.PathName -imatch "Temp|\\AppData\\|\\Users\\.*\\AppData")) -or
        ($_.PathName -and ($_.PathName -imatch "\\Windows\\Temp"))
    }
    $svcSuspicious | Export-Csv -Path (Join-Path $OutDir "services_suspicious.csv") -NoTypeInformation -Encoding UTF8
    $svcSuspicious | Out-String | Set-Content (Join-Path $OutDir "services_suspicious.txt")
} catch {
    "Cannot enumerate services: $_" | Out-File (Join-Path $OutDir "services_error.txt")
}
# 5) External established network connections with owning process
Write-Output "Scanning established network connections for external endpoints..."

function Is-PrivateIP($ip) {
    if (-not $ip) { return $true }
    if ($ip -match "^127\.|^::1$|^fe80:|^fc00:|^fd00:") { return $true }
    if ($ip -match "^10\.") { return $true }
    if ($ip -match "^192\.168\.") { return $true }
    if ($ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    return $false
}

$netconns = @()
try {
    $tcp = Get-NetTCPConnection -State Established -ErrorAction Stop
    foreach ($c in $tcp) {
        $ra = $c.RemoteAddress
        if (-not (Is-PrivateIP $ra)) {
            $procName = ""
            try {
                $procName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            } catch {}
            $netconns += [PSCustomObject]@{
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $ra
                RemotePort    = $c.RemotePort
                OwningProcess = $c.OwningProcess
                ProcessName   = $procName
            }
        }
    }
}
catch {
    # Fallback for older systems: parse netstat output
    $ns = netstat -ano | Select-String ESTABLISHED
    foreach ($line in $ns) {
        $parts = ($line -split "\s+") | Where-Object { $_ -ne "" }
        if ($parts.Length -ge 5) {
            $remote = $parts[2].Split(':')[0]
            if (-not (Is-PrivateIP $remote)) {
                $pid = $parts[-1]
                $pname = ""
                try { $pname = (Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName } catch {}
                $netconns += [PSCustomObject]@{
                    Local         = $parts[1]
                    Remote        = $parts[2]
                    PID           = $pid
                    ProcessName   = $pname
                }
            }
        }
    }
}

$netconns | Export-Csv -Path (Join-Path $OutDir "network_external_connections.csv") -NoTypeInformation -Encoding UTF8
$netconns | Out-String | Set-Content (Join-Path $OutDir "network_external_connections.txt")
