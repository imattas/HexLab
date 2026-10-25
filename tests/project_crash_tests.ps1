param([Parameter(Mandatory=$true)][string]$Helper,[Parameter(Mandatory=$true)][string]$FixtureDirectory)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $FixtureDirectory | Out-Null
foreach($phase in @('before','during','after')) {
    $projectPath=Join-Path $FixtureDirectory ([Guid]::NewGuid().ToString()+'.hxproj')
    $start=New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName=$Helper
    $start.Arguments='--write "'+$projectPath+'" '+$phase
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardInput=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $child=New-Object System.Diagnostics.Process
    $child.StartInfo=$start
    try {
        if(-not $child.Start()){throw 'Cannot start crash helper'}
        $line=$child.StandardOutput.ReadLineAsync()
        if(-not $line.Wait(10000)){throw "Checkpoint timed out: $phase"}
        if($line.Result -ne 'CHECKPOINT'){throw "Missing checkpoint: $phase; $($line.Result)"}
        # Kill only this explicitly started helper, at its signaled transaction point.
        $child.Kill()
        if(-not $child.WaitForExit(5000)){throw 'Crash helper did not terminate'}
        $expected=if($phase -eq 'after'){'1'}else{'0'}
        & $Helper --verify $projectPath $expected
        if($LASTEXITCODE -ne 0){throw "Recovery failed at $phase"}
    } finally {
        if(-not $child.HasExited){$child.Kill();$child.WaitForExit(5000) | Out-Null}
        $child.Dispose()
        foreach($suffix in @('','-wal','-shm')){Remove-Item -LiteralPath ($projectPath+$suffix) -ErrorAction SilentlyContinue}
    }
}
