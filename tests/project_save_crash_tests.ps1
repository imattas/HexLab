param([Parameter(Mandatory=$true)][string]$Helper,[Parameter(Mandatory=$true)][string]$FixtureDirectory)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $FixtureDirectory | Out-Null
function Start-HeldHelper([string]$mode,[string]$projectPath,[string]$phase){
    $start=New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName=$Helper
    $start.Arguments=$mode+' "'+$projectPath+'" '+$phase
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $child=New-Object System.Diagnostics.Process;$child.StartInfo=$start
    if(-not $child.Start()){throw 'Cannot start save helper'}
    try {
        $line=$child.StandardOutput.ReadLineAsync()
        if(-not $line.Wait(10000)){throw "Save checkpoint timed out: $phase"}
        if($line.Result -ne 'CHECKPOINT'){throw "Missing save checkpoint: $phase; $($line.Result)"}
        return $child
    } catch {if(-not $child.HasExited){$child.Kill();$child.WaitForExit(5000) | Out-Null};$child.Dispose();throw}
}
foreach($existing in @($false,$true)){
    foreach($phase in @('copied','before','after')){
        $casePath=Join-Path $FixtureDirectory ([Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $casePath | Out-Null
        $projectPath=Join-Path $casePath 'target.hxproj'
        if($existing){& $Helper --baseline $projectPath unused;if($LASTEXITCODE -ne 0){throw 'Baseline creation failed'}}
        $child=Start-HeldHelper '--save' $projectPath $phase
        try {
            $child.Kill();if(-not $child.WaitForExit(5000)){throw 'Save helper did not terminate'}
            if($phase -eq 'after'){& $Helper --verify $projectPath replacement;if($LASTEXITCODE -ne 0){throw 'Complete destination recovery failed'}}
            elseif($existing){& $Helper --verify $projectPath baseline;if($LASTEXITCODE -ne 0){throw 'Preceding destination was damaged'}}
            elseif(Test-Path -LiteralPath $projectPath){throw 'Incomplete first save became visible'}
        } finally {if(-not $child.HasExited){$child.Kill();$child.WaitForExit(5000) | Out-Null};$child.Dispose()}
    }
}
$leasePath=Join-Path $FixtureDirectory ([Guid]::NewGuid().ToString()+'.hxproj')
$owner=Start-HeldHelper '--lease-owner' $leasePath 'hold'
try {
    & $Helper --lease-check $leasePath readonly;if($LASTEXITCODE -ne 0){throw 'Duplicate process did not become readonly'}
    $owner.Kill();if(-not $owner.WaitForExit(5000)){throw 'Lease owner did not terminate'}
    & $Helper --lease-check $leasePath editable;if($LASTEXITCODE -ne 0){throw 'Lease was not released by process death'}
} finally {if(-not $owner.HasExited){$owner.Kill();$owner.WaitForExit(5000) | Out-Null};$owner.Dispose()}
# Keep per-case artifacts in this ignored validation directory for inspection.
