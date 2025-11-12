<#
scan-network-fixed.ps1
- Auto-detects IPv4 + prefix or accepts -Cidr "192.168.1.0/24"
- Performs chunked ping sweep then collects DNS, ARP/MAC, quick TCP port checks
- Saves results to CSV in $env:TEMP
Note: Run only on networks you are authorized to scan.
#>

param(
  [string]$Cidr
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log { param($s) Write-Host $s }

# --- Helpers ---
function Get-LocalNetwork {
  try {
    # Prefer Get-NetIPAddress when available (Windows 8+/Server 2012+)
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
      $iface = Get-NetIPInterface -AddressFamily IPv4 |
               Where-Object { $_.ConnectionState -eq 'Connected' -and $_.InterfaceOperationalStatus -eq 'Up' } |
               Sort-Object -Property InterfaceMetric |
               Select-Object -First 1
      if ($iface) {
        $ipObj = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $iface.InterfaceIndex |
                 Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixLength -gt 0 } | Select-Object -First 1
        if ($ipObj) {
          return @{ IP = $ipObj.IPAddress; Prefix = [int]$ipObj.PrefixLength }
        }
      }
    }
  } catch { }

  # Fallback: parse ipconfig
  try {
    $txt = ipconfig /all 2>&1
    $ip = $null; $mask = $null
    foreach ($line in $txt) {
      if ($line -match 'IPv4 Address.*:\s*([\d\.]+)') { $ip = $matches[1] }
      if ($line -match 'Subnet Mask.*:\s*([\d\.]+)') { $mask = $matches[1] }
      if ($ip -and $mask) {
        # convert mask to prefix
        $parts = $mask.Split('.') | ForEach-Object {[int]$_}
        $bin = ($parts | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') }) -join ''
        $prefix = ($bin.ToCharArray() | Where-Object { $_ -eq '1' }).Count
        return @{ IP = $ip; Prefix = $prefix }
      }
    }
  } catch { }

  throw "Failed to auto-detect local IPv4 address. Provide -Cidr."
}

function IpToUint32([string]$ip) {
  $b = $ip.Split('.') | ForEach-Object {[uint32]$_}
  return ($b[0] -shl 24) -bor ($b[1] -shl 16) -bor ($b[2] -shl 8) -bor $b[3]
}
function Uint32ToIp([uint32]$n) {
  $b1 = ($n -shr 24) -band 0xFF
  $b2 = ($n -shr 16) -band 0xFF
  $b3 = ($n -shr 8) -band 0xFF
  $b4 = $n -band 0xFF
  return "$b1.$b2.$b3.$b4"
}

function Get-HostEnumerableFromCIDR([string]$baseIp, [int]$prefix) {
  $ipInt = [uint32](IpToUint32 $baseIp)
  $hostBits = 32 - $prefix
  if ($hostBits -le 0) { return @() }
  $mask = ([uint32]0xFFFFFFFF) -shl $hostBits
  $net = $ipInt -band $mask
  $first = $net + 1
  $last = $net + ([uint32]([math]::Pow(2,$hostBits) - 2))
  # return array of strings
  $list = New-Object System.Collections.Generic.List[System.String]
  for ($i = $first; $i -le $last; $i++) {
    $list.Add((Uint32ToIp [uint32]$i))
  }
  return $list
}

function Get-ARP {
  param($ip)
  try {
    $out = arp -a 2>$null
    foreach ($line in $out) {
      if ($line -match "^\s*([0-9]{1,3}(\.[0-9]{1,3}){3})\s+([0-9A-Fa-f:-]{17,17})") {
        if ($matches[1] -eq $ip) { return ($matches[3] -replace '-',' :') -replace ' ','': ($matches[3]) }
      }
    }
  } catch {}
  return $null
}

function Test-Port {
  param($ip,$port,[int]$timeout=250)
  try {
    $tc = New-Object System.Net.Sockets.TcpClient
    $iar = $tc.BeginConnect($ip,$port,$null,$null)
    $wait = $iar.AsyncWaitHandle.WaitOne($timeout)
    if (-not $wait) { $tc.Close(); return $false }
    $tc.EndConnect($iar)
    $tc.Close()
    return $true
  } catch { return $false }
}

function Get-DeviceInfo {
  param($ip)
  $obj = [PSCustomObject]@{
    IP = $ip
    Alive = $false
    HostName = ''
    MAC = ''
    OpenPorts = @()
  }
  if (Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) {
    $obj.Alive = $true
    try { $obj.HostName = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
    Start-Sleep -Milliseconds 30
    $mac = Get-ARP -ip $ip
    if (-not $mac) {
      Test-Connection -ComputerName $ip -Count 1 -Quiet | Out-Null
      $mac = Get-ARP -ip $ip
    }
    if ($mac) { $obj.MAC = $mac }
    $ports = 80,443,22,3389,445,139,161,8080
    foreach ($p in $ports) {
      if (Test-Port -ip $ip -port $p -timeout 300) { $obj.OpenPorts += $p }
    }
  }
  return $obj
}

# ---------------- main ----------------
try {
  if (-not $Cidr) {
    $net = Get-LocalNetwork
    $ip = $net.IP; $prefix = [int]$net.Prefix
    Write-Log "Detected: $ip/$prefix"
  } else {
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { throw "Bad CIDR" }
    $ip = $parts[0]; $prefix = [int]$parts[1]
    Write-Log "Using CIDR: $ip/$prefix"
  }

  $hostCount = [math]::Pow(2,(32 - $prefix)) - 2
  if ($hostCount -gt 65536) { throw "Network too big ($hostCount hosts). Use smaller CIDR." }

  $hosts = Get-HostEnumerableFromCIDR -baseIp $ip -prefix $prefix
  Write-Log "Scanning $($hosts.Count) hosts..."

  $chunk = 120
  $results = @()

  for ($i=0; $i -lt $hosts.Count; $i += $chunk) {
    $slice = $hosts[$i..([math]::Min($i+$chunk-1,$hosts.Count-1))]
    # fast parallel ping using Test-Connection with array input
    $aliveFlags = $null
    try {
      $aliveFlags = Test-Connection -ComputerName $slice -Count 1 -ErrorAction SilentlyContinue -Quiet
    } catch {
      # fallback single
      $aliveFlags = foreach ($h in $slice) { Test-Connection -ComputerName $h -Count 1 -Quiet }
    }

    for ($j=0; $j -lt $slice.Count; $j++) {
      $h = $slice[$j]
      $alive = $false
      if ($aliveFlags -is [System.Collections.IEnumerable]) { $alive = [bool]$aliveFlags[$j] } else { $alive = [bool]$aliveFlags }
      if ($alive) {
        $info = Get-DeviceInfo -ip $h
        $results += $info
        $ports = if ($info.OpenPorts.Count) { $info.OpenPorts -join ',' } else { '-' }
        Write-Host ("{0}  {1,-40}  MAC:{2,-17} Ports:{3}" -f $h, ($info.HostName -ne '' ? $info.HostName : '-'), ($info.MAC -ne '' ? $info.MAC : '-'), $ports)
      }
    }
  }

  $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $out = Join-Path $env:TEMP "network_scan_$ts.csv"
  $results | Select-Object IP,HostName,MAC,@{Name='OpenPorts';Expression={$_.OpenPorts -join ','}} |
    Export-Csv -Path $out -NoTypeInformation -Encoding UTF8

  Write-Log "`nScan complete. Found $($results.Count) hosts. CSV: $out"
} catch {
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}
