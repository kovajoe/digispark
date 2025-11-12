# === main.ps1 ===
Clear-Host
$owner  = 'kovajoe'
$repo   = 'digispark'
$branch = 'main'

# Fetch repo contents
$u = "https://api.github.com/repos/$owner/$repo/contents?ref=$branch"
$hdr = @{ 'User-Agent' = 'DigisparkClient' }

try {
    $items = Invoke-RestMethod -Headers $hdr -Uri $u -ErrorAction Stop
} catch {
    Write-Host "❌ Cannot fetch file list. Check internet or repo name."
    exit
}

# Filter only script files (.ps1, .bat, .cmd)
$files = $items | Where-Object { $_.name -match '\.ps1$|\.bat$|\.cmd$' }

if (-not $files) {
    Write-Host "No script files found in repo root."
    exit
}

Write-Host "`nAvailable scripts:`n"
for ($i=0; $i -lt $files.Count; $i++) {
    Write-Host "[$($i+1)] $($files[$i].name)"
}

# Choose file number
$sel = Read-Host "`nEnter script number to download and run (0 to cancel)"
if ([int]$sel -le 0 -or [int]$sel -gt $files.Count) {
    Write-Host "Cancelled."
    exit
}

# Download and run automatically
$choice = $files[[int]$sel - 1]
$dl = $choice.download_url
$out = Join-Path $env:TEMP $choice.name

Write-Host "`nDownloading: $($choice.name)"
Invoke-WebRequest -Uri $dl -OutFile $out -UseBasicParsing

Write-Host "`nRunning script: $out"
Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$out -Verb RunAs
