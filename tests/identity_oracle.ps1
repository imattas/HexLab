param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
