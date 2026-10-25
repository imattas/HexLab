param(
    [Parameter(Mandatory=$true)][string]$Bochs,
    [Parameter(Mandatory=$true)][string]$Config,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$probeStart=New-Object System.Diagnostics.ProcessStartInfo
$probeStart.FileName=$Bochs
$probeStart.Arguments='-q -f "'+$Config+'"'
$probeStart.UseShellExecute=$false
$probeStart.CreateNoWindow=$true
$probeStart.RedirectStandardOutput=$true
$probeStart.RedirectStandardError=$true
$probeStart.RedirectStandardInput=$true
$probeProcess=New-Object System.Diagnostics.Process
$probeProcess.StartInfo=$probeStart
$probeLines=New-Object System.Collections.Generic.List[string]
$deadline=[Diagnostics.Stopwatch]::StartNew()
$probeStarted=$false
try {
    if (!$probeProcess.Start()) { throw 'Cannot start precise16 oracle' }
    $probeStarted=$true
    $probeError=$probeProcess.StandardError.ReadToEndAsync()
    $pendingLine=$probeProcess.StandardOutput.ReadLineAsync()
    $completed=$false
    $outputSize=0
    while ($deadline.Elapsed.TotalSeconds -lt 8) {
        if ($pendingLine.Wait(50)) {
            $line=$pendingLine.Result
            if ($null -eq $line) { throw 'Precise16 oracle exited before its completion record' }
            $outputSize+=$line.Length+1
            if ($outputSize -gt 65536) { throw 'Precise16 oracle output exceeded64KiB' }
            $probeLines.Add($line)
            if ($line -eq 'DONE') { $completed=$true; break }
            $pendingLine=$probeProcess.StandardOutput.ReadLineAsync()
        }
        if ($probeProcess.HasExited) { throw 'Precise16 oracle terminated before the controlled halt' }
    }
    if (!$completed) { throw 'Precise16 oracle exceeded its8-second execution deadline' }
    if ($probeProcess.HasExited) { throw 'Precise16 oracle exited instead of reaching the controlled halt' }
    # The authored image emits DONE and halts with interrupts off. Stop only
    # this process. Avoid the vendor binary's intermittent ACPI teardown AV;
    # neither an emulated fault nor a host crash counts as successful execution.
    $probeProcess.Kill()
    $probeProcess.WaitForExit()
    [IO.File]::WriteAllText($Output,($probeLines -join "`n")+"`n",[Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($Output+'.stderr.txt',$probeError.Result,[Text.Encoding]::ASCII)
} finally {
    if ($probeStarted -and !$probeProcess.HasExited) { $probeProcess.Kill(); $probeProcess.WaitForExit() }
    $probeProcess.Dispose()
}
