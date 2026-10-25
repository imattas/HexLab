param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
$actual=(Get-FileHash -LiteralPath (Join-Path $Path 'patched.bin') -Algorithm SHA256).Hash.ToLowerInvariant()
$expected=(Get-Content -LiteralPath (Join-Path $Path 'patched.sha256') -Raw -Encoding ASCII).Trim()
if($actual -cne $expected){throw 'Export receipt differs from independent Windows SHA-256'}
