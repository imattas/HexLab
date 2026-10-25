param([Parameter(Mandatory=$true)][string]$Bin,
      [Parameter(Mandatory=$true)][string]$Report,
      [switch]$Production)
$ErrorActionPreference = 'Stop'
$binaryRoot = (Resolve-Path -LiteralPath $Bin).Path
$dumpbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe'
if (!(Test-Path -LiteralPath $dumpbin -PathType Leaf)) { throw 'Required MSVC binary inspection tool is missing' }
$reportPath = [IO.Path]::GetFullPath($Report)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($reportPath)) | Out-Null
$components = @('core','image','processors','loaders','analysis','database','workspace','sqlite3')
$allowed = @{
    core=@(); image=@('core'); processors=@('core'); loaders=@('core','image');
    analysis=@('core','image','processors');
    database=@('core','image','processors','loaders','analysis','sqlite3');
    workspace=@('core','image','processors','loaders','analysis','database','sqlite3'); sqlite3=@()
}
if ($Production) {
    $cache = Join-Path (Split-Path (Split-Path $binaryRoot -Parent) -Parent) 'CMakeCache.txt'
    if (!(Test-Path -LiteralPath $cache -PathType Leaf) -or
        !(Select-String -LiteralPath $cache -Pattern '^BUILD_TESTING:BOOL=OFF$' -Quiet)) {
        throw 'Production audit requires the actual BUILD_TESTING=OFF build cache'
    }
}
$records = foreach ($component in $components) {
    $path = Join-Path $binaryRoot "hexlab_$component.dll"
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing engine runtime: $path" }
    $dependencyOutput = & $dumpbin /dependents $path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect dependencies: $path" }
    $exportOutput = & $dumpbin /exports $path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect exports: $path" }
    $dependencyText = $dependencyOutput -join "`n"
    $exportText = $exportOutput -join "`n"
    $dependencies = @([regex]::Matches($dependencyText, '(?im)^\s*([^\s]+\.dll)\s*$') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
    if (!$dependencies.Count) { throw "No actual PE dependency records: $path" }
    $forbidden = @($dependencies | Where-Object { $_ -match '^(wx|qt)|llvm|clang|capstone|zydis' })
    if ($forbidden.Count) { throw "Engine acquired GUI/foreign decoder/oracle dependencies: $path -> $forbidden" }
    foreach ($dependency in $dependencies) {
        if ($dependency -match '^hexlab_(.+)\.dll$' -and $Matches[1] -notin $allowed[$component]) {
            throw "Engine dependency exceeds declared direction: $component -> $dependency"
        }
    }
    $hooks = @([regex]::Matches($exportText, '(?m)^.*workspace_testing.*$') | ForEach-Object Value)
    if ($Production -and $hooks.Count) { throw "Production engine exports private workspace test hooks: $path" }
    if (!$Production -and $component -eq 'workspace' -and $hooks.Count -ne 3) { throw 'Developer runtime lost the three explicit workspace test hooks' }
    $stem = Join-Path ([IO.Path]::GetDirectoryName($reportPath)) "hexlab_$component"
    $dependencyText | Set-Content -LiteralPath ($stem + '.dependents.txt')
    $exportText | Set-Content -LiteralPath ($stem + '.exports.txt')
    [pscustomobject]@{ name=$component; path=$path; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();
        dependencies=$dependencies; private_workspace_hooks=$hooks.Count }
}
if (@(Get-ChildItem -LiteralPath $binaryRoot -File -Filter 'hexlab_*.dll').Count -ne 8) { throw 'Expected exactly eight engine DLLs' }
$result = [pscustomobject]@{ schema=1; bin=$binaryRoot; production=$Production.IsPresent;
    tool=$dumpbin; tool_sha256=(Get-FileHash -LiteralPath $dumpbin -Algorithm SHA256).Hash.ToLowerInvariant(); engines=$records }
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath
$records | Select-Object name,private_workspace_hooks,@{Name='dependencies';Expression={$_.dependencies -join ';'}} | Format-Table -AutoSize
Write-Output "PASS eight engine dependency/test-export boundaries: $reportPath"
