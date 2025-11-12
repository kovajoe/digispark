<#
.SYNOPSIS
  Discover online hosts in the local network, with basic device info.

.DESCRIPTION
  - Auto-detects local IPv4 + prefix or accepts a CIDR via -Cidr.
  - Pings hosts in parallel (chunked) to find alive hosts.
  - Gathers DNS name, ARP/MAC, basic port checks (common ports), and NetBIOS name.
  - Outputs results to console and saves CSV to $env:TEMP\network_scan_<timestamp>.csv

.PARAMETER Cidr
  Optional. Provide a network in CIDR format (e.g. 192.168.1.0/24). If not supplied, script auto-detects.
.EXAMPLE
  .\scan-network.ps1
  .\scan-network.ps1 -Cidr "10.10.0.0/24"
#>

param(
  [string]$Cidr
)

function Get-LocalIPv4Network {
  # Try Get-NetIPAddress (modern), fallback to ipconfig parsing
  try {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias ((Get-NetIPInterface | Where-Object {$_.ConnectionState -eq "Connected"} | Select-Object -First 1).InterfaceAlias) -ErrorAction Stop |
          Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixLength -gt 0 } | Select-Object -First 1
    if ($ip) {
      return @{ IP = $ip.IPAddress; Prefix = $ip.PrefixLength }
    }
  } catch { }

  # Fallback: parse ipconfig
  $cfg = ipconfig
  foreach ($line in $cfg) {
    if ($line -match 'IPv4 Address.*:\s*([\d\.]+)') {
      $ipAddr = $matches[1]
    }
    if ($line -match 'Subnet Mask.*:\s*([\d\.]+)') {
      $sub = $matches[1]
      if ($ipAddr) {
        # convert mask to prefix
        $bytes = $sub.Split('.') | ForEach-Object {[int]$_}
        $bin = ($bytes | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') }) -join ''
        $prefix = ($bin -split '1').Length - 1
        return @{ IP = $ipAddr; Prefix = $prefix }
      }
    }
  }
  throw "Unable to auto-detect local IPv4 address. Provide -Cidr manually."
}

function Get-IPRangeFromCidr {
  param($cidr)
  # cidr must be like x.x.x.x/nn
  $parts = $cidr -split '/'
  if ($parts.Count -ne 2) { throw "Invalid CIDR: $cidr" }
  $ip = [System.Net.IPAddress]::Parse($parts[0])
  $pref = [int]$parts[1]
  # compute network and broadcast
  $ipBytes = [BitConverter]::ToUInt32([System.Net.IPAddress]::HostToNetworkOrder([int][BitConverter]::ToInt32($ip.GetAddressBytes(),0)),0)
  $mask = -bor (-shl 0xffffffff, (32 - $pref))   # not portable very terse - use bigint approach
  # safer compute mask:
  $maskInt = [uint32]((([math]::Pow(2,32) - 1) - ([math]::Pow(2, (32-$pref)) - 1)))
  $netInt = $ipBytes -band $maskInt
  $first = $netInt + 1
  $last = ($netInt + ([uint32]([math]::Pow(2, (32 - $pref)) - 1))) - 1
  $hosts = @()
  for ($i = $first; $i -le $last; $i++) {
    # convert back to dotted
    $b = [BitConverter]::GetBytes([uint32]$i)
    $b = [Array]::Reverse($b); # ensure network order -> host order
    $ipAddr = [System.Net.IPAddress]::Parse(($b[0]).ToString() + "." + ($b[1]).ToString() + "." + ($b[2]).ToString() + "." + ($b[3]).ToString())
    $hosts += $ipAddr.IPAddressToString
  }
  return $hosts
}

function Get-HostsFromCIDRAlt {
  param($ip, $prefix)
  # Using IPNetwork class from .NET not available by default; do manual compute simpler:
  # Convert IP to UInt32:
  $bytes = $ip.Split('.') | ForEach-Object {[byte]$_}
  $ipInt = ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor ([uint32]$bytes[3])
  $hostBits = 32 - [int]$prefix
  if ($hostBits -le 0) { return @() }
  $numHosts = [uint32]([math]::Pow(2, $hostBits) - 2)  # exclude network and broadcast
  $netInt = $ipInt -band ([uint32](-bor ((-bor 0,0))))
  # easier: compute net by zeroing host bits
  $maskUint = ([uint32](((-band ([uint32]0xffffffff), ([uint32]0xffffffff << $hostBits)))))
  # simpler compute mask via shift:
  $maskUint = ([uint32](([uint64]0xffffffff) - ([math]::Pow(2,$hostBits) - 1)))
  $net = $ipInt -band $maskUint
  $first = $net + 1
  $last = $net + [uint32]([math]::Pow(2,$hostBits) - 2)
  $list = for ($i = $first; $i -le $last; $i++) {
    $b1 = (($i -shr 24) -band 0xFF)
    $b2 = (($i -shr 16) -band 0xFF)
    $b3 = (($i -shr 8) -band 0xFF)
    $b4 = ($i -band 0xFF)
    "$b1.$b2.$b3.$b4"
  }
  return $list
}

function Get-MACFromArp {
  param($ip)
  $arp = arp -a $ip 2>$null
  if ($arp -and $arp -match "([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}") {
    return ($matches[0] -replace '-',':')
  }
  # fallback: parse arp -a table
  $table = arp -a | Where-Object {$_ -match $ip}
  if ($table -match "([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}") { return ($matches[0] -replace '-',':') }
  return $null
}

function Get-DeviceInfo {
  param($ip)
  $info = [PSCustomObject]@{
    IP = $ip
    Alive = $false
    HostName = ''
    MAC = ''
    OpenPorts = @()
    NetBIOS = ''
  }

  if ((Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
    $info.Alive = $true
    # DNS reverse lookup
    try { $info.HostName = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $info.HostName = '' }

    # ARP / MAC
    Start-Sleep -Milliseconds 20
    $mac = Get-MACFromArp -ip $ip
    if (-not $mac) {
      # populate ARP by pinging then re-check
      Test-Connection -ComputerName $ip -Count 1 | Out-Null
      $mac = Get-MACFromArp -ip $ip
    }
    $info.MAC = $mac

    # Common ports quick check
    $ports = 80,443,22,23,3389,445,139,161
    foreach ($port in $ports) {
      try {
        $res = Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue
        if ($res -and $res.TcpTestSucceeded) { $info.OpenPorts += $port }
      } catch { }
    }

    # Try NetBIOS name
    try {
      $nb = nbstat -A $ip 2>$null
      if ($nb -match 'Name') {
        # parse name line if exists
        $lines = $nb -split "`r?`n"
        foreach ($l in $lines) {
          if ($l -match '^\s*<00>\s+UNIQUE\s+(.+)$') {
            $info.NetBIOS = ($l -replace '^\s*','') ; break
          }
        }
      }
    } catch {}
  }

  return $info
}

# ---------------- main ----------------

Write-Host "Network scanner - quick discover" -ForegroundColor Cyan

if (-not $Cidr) {
  try {
    $net = Get-LocalIPv4Network
    $ip = $net.IP
    $pref = $net.Prefix
    Write-Host "Detected IP: $ip / $pref"
  } catch {
    Write-Host "Auto-detect failed: $_" -ForegroundColor Red
    exit 1
  }
} else {
  $parts = $Cidr -split '/'
  if ($parts.Count -ne 2) { Write-Host "Invalid CIDR format. Use x.x.x.x/nn" ; exit 1 }
  $ip = $parts[0]; $pref = [int]$parts[1]
  Write-Host "Using provided CIDR: $ip / $pref"
}

# Build host list: avoid huge networks
$hostCount = [math]::Pow(2, (32 - $pref)) - 2
if ($hostCount -gt 4096) {
  Write-Host "Network too large ($hostCount hosts). Limit is 4096. Provide a narrower CIDR or run from dedicated scanner." -ForegroundColor Yellow
  exit 1
}

# Generate hosts
$hosts = Get-HostsFromCIDRAlt -ip $ip -prefix $pref

Write-Host ("Scanning {0} hosts (concurrency chunked)" -f $hosts.Count) -ForegroundColor Green

# Parameters
$chunk = 80   # number of hosts to probe per Test-Connection call (tweak as needed)
$results = @()

for ($i = 0; $i -lt $hosts.Count; $i += $chunk) {
  $slice = $hosts[$i..([math]::Min($i+$chunk-1,$hosts.Count-1))]
  # Test-Connection accepts arrays and returns faster than individual pings in many cases
  $aliveFlags = $null
  try {
    $aliveFlags = Test-Connection -ComputerName $slice -Count 1 -ErrorAction SilentlyContinue -Quiet
  } catch {
    # fallback: sequential
    $aliveFlags = foreach ($h in $slice) { Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue }
  }

  for ($j = 0; $j -lt $slice.Count; $j++) {
    $h = $slice[$j]
    $alive = $false
    if ($aliveFlags -is [System.Collections.IEnumerable]) {
      $alive = [bool]$aliveFlags[$j]
    } else {
      $alive = [bool]$aliveFlags
    }

    if ($alive) {
      # gather more info (not too slow)
      $info = Get-DeviceInfo -ip $h
      $results += $info
      $fmtPorts = if ($info.OpenPorts) { ($info.OpenPorts -join ',') } else { '-' }
      Write-Host ("{0}  {1}  {2}  MAC:{3}  Ports:{4}" -f $h, ($info.HostName -ne '' ? $info.HostName : '-'), ($info.NetBIOS -ne '' ? $info.NetBIOS : '-'), ($info.MAC -ne '' ? $info.MAC : '-'), $fmtPorts)
    }
  }
}

# Save CSV
$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$outFile = Join-Path $env:TEMP "network_scan_$ts.csv"
$results | Select-Object IP,HostName,NetBIOS,MAC,@{n='OpenPorts';e={($_.OpenPorts -join ',')}} | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

Write-Host "`nScan complete. Found $($results.Count) hosts alive."
Write-Host "Results saved to: $outFile"
