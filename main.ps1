# === main.ps1 ===
Clear-Host
$owner  = 'kovajoe'
$repo   = 'digispark'
$branch = 'main'

# Get list of files in repo
$u = "https://api.github.com/repos/$owner/$repo/contents?ref=$branch"
$hdr = @{ 'User-Agent' = 'DigisparkClient' }

try {
    $items = Invoke-RestMethod -Headers $hdr -Uri $u -ErrorAction Stop
} catch {
    Write-Host "❌ Cannot fetch file list. Check internet or repo name."
    exit
}

# List .ps1, .bat, .cmd, etc.
$files = $items | Where-Object { $_.name -match '\.ps1$|\.bat$|\.cmd$' }

if (-not $files) {
    Write-Host "No script files found in repo root."
    exit
}

Write-Host "`nAvailable scripts:`n"
for ($i=0; $i -lt $files.Count; $i++) {
    Write-Host "[$($i+1)] $($files[$i].name)"
}

# Choose one
$sel = Read-Host "`nEnter script number to download (0 to cancel)"
if ([int]$sel -le 0 -or [int]$sel -gt $files.Count) {
    Write-Host "Cancelled."
    exit
}

$choice = $files[[int]$sel - 1]
$dl = $choice.download_url
$out = Join-Path $env:TEMP $choice.name

# Download it
Write-Host "`nDownloading: $($choice.name)"
Invoke-WebRequest -Uri $dl -OutFile $out -UseBasicParsing

Write-Host "`nSaved to: $out"
Write-Host "Preview (first 20 lines):`n"
Get-Content $out -TotalCount 20

$confirm = Read-Host "`nType YES to run, anything else to cancel"
if ($confirm -eq 'YES') {
    Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$out -Verb RunAs
} else {
    Write-Host "Cancelled."
}
