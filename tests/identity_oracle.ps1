param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
$sha256=[Security.Cryptography.SHA256]::Create()
try {
    $digest=$sha256.ComputeHash([IO.File]::ReadAllBytes($Path))
    ([BitConverter]::ToString($digest)).Replace('-','').ToLowerInvariant()
} finally {
    $sha256.Dispose()
}
