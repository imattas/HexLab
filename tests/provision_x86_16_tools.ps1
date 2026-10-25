param([switch]$Download,[switch]$Offline,[string]$Destination)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($Download -and $Offline) { throw 'Choose Download or Offline' }
$projectRoot=Split-Path -Parent $PSScriptRoot
$toolRoot=Join-Path $projectRoot 'out/tools'
if ($Destination) {
    $allowedRoot=[IO.Path]::GetFullPath($toolRoot)
    $toolRoot=[IO.Path]::GetFullPath($Destination)
    if (!$toolRoot.Equals($allowedRoot,[StringComparison]::OrdinalIgnoreCase) -and
        !$toolRoot.StartsWith($allowedRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Test tool destination must stay within this workspace out/tools directory'
    }
}
$archiveRoot=Join-Path $toolRoot 'downloads'
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/x86_16_oracle/tools.json') -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1) { throw 'Unsupported test tool manifest' }
New-Item -ItemType Directory -Path $archiveRoot -Force | Out-Null
function Test-PinnedFiles($root,$files) {
    foreach ($entry in $files) {
        $file=Join-Path $root $entry.path
        if (!(Test-Path -LiteralPath $file)) { return $false }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { return $false }
    }
    return $true
}
foreach ($tool in $manifest.tools) {
    $archive=Join-Path $archiveRoot $tool.archive
    if (!(Test-Path -LiteralPath $archive)) {
        if (!$Download -or $Offline) { throw "Missing cached $($tool.archive); use -Download once to provision locally" }
        $ProgressPreference='SilentlyContinue'
        Invoke-WebRequest -Uri $tool.url -OutFile $archive -UseBasicParsing -TimeoutSec 180
    }
    $digest=(Get-FileHash -LiteralPath $archive -Algorithm $tool.algorithm).Hash.ToLowerInvariant()
    if ($digest -ne $tool.digest) { throw "Test tool archive hash mismatch: $($tool.archive)" }
    $destination=Join-Path $toolRoot $tool.directory
    if (!(Test-PinnedFiles $destination $tool.files)) {
        if ($tool.format -eq 'zip') {
            Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
        } else {
            $sevenZip=Join-Path $env:ProgramFiles '7-Zip/7z.exe'
            if (!(Test-Path -LiteralPath $sevenZip)) {
                $command=Get-Command 7z -ErrorAction SilentlyContinue
                if (!$command) { throw 'A current7-Zip command supporting NSIS archives is required' }
                $sevenZip=$command.Source
            }
            $listing=& $sevenZip l $archive
            if ($LASTEXITCODE -ne 0 -or !($listing -match '^Type = Nsis')) {
                throw 'This7-Zip cannot read the pinned NSIS archive; use a current7-Zip build'
            }
            $arguments=@('x',$archive,"-o$destination",'-aoa')
            if ($tool.format -eq 'nsis-qemu-subset') {
                $arguments+=@('qemu-system-i386.exe','*.dll','share/*','COPYING*','doc/*')
            }
            & $sevenZip @arguments | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Local extraction failed for $($tool.name)" }
        }
    }
    if (!(Test-PinnedFiles $destination $tool.files)) { throw "Extracted test tool hash mismatch: $($tool.name)" }
    foreach ($notice in $tool.notices) {
        if (!(Test-Path -LiteralPath (Join-Path $destination $notice))) { throw "Missing vendor notice: $notice" }
    }
    Write-Output "Verified local test tool: $($tool.name)"
}
