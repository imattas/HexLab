param([Parameter(Mandatory=$true)][string]$Prefix,
      [ValidateSet('x86-64','x86-32','x86-16')][string]$Mode='x86-64',
      [string]$InputFixture='', [string]$ExpectedLocation='', [string]$CaptureName='',
      [string]$NavigateTo='')
$ErrorActionPreference = 'Stop'
$bin = [IO.Path]::GetFullPath((Join-Path $Prefix 'bin'))
$fixtureName=if($Mode -eq 'x86-32'){'minimal32.exe'}else{'metadata64.exe'}
$fixture = Join-Path $Prefix ('test-fixtures/'+$fixtureName)
$capturePrefix=if($Mode -eq 'x86-32'){'installed-x86-32'}else{'installed'}
$expectedAddress=if($Mode -eq 'x86-32'){'0x401000'}else{'0x140001000'}
if($Mode -eq 'x86-16') {
    $capturePrefix='installed-x86-16'
    $expectedAddress='1000:0000'
    $profile=Join-Path $Prefix 'test-fixtures/installed16.profile'
    [IO.File]::WriteAllText($profile,"hexlab-x86-profile 1`nenvironment real386`na20 enabled`nload 0x10000`nentry 7 0`nstack none`ndomains 1`ndomain 7 0x1000 code `"text`" real`n",(New-Object Text.UTF8Encoding $false))
    $fixture=Join-Path $Prefix 'test-fixtures/installed16.hxproj'
    & (Join-Path $bin 'hexlab_cli.exe') project create $fixture --input (Join-Path $Prefix 'test-fixtures/raw.bin') --format raw --profile $profile --replace
    if($LASTEXITCODE -ne 0) { throw 'Installed CLI could not create the real16 application fixture' }
}
if($InputFixture) { $fixture=[IO.Path]::GetFullPath($InputFixture) }
if($ExpectedLocation) { $expectedAddress=$ExpectedLocation }
if($CaptureName) { $capturePrefix=$CaptureName }
if(-not (Test-Path -LiteralPath $fixture -PathType Leaf)) { throw "Installed runtime fixture missing: $fixture" }
$artifact = Join-Path $Prefix 'validation/actual-application'
New-Item -ItemType Directory -Force -Path $artifact | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class HexLabInstalledWindow {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left,Top,Right,Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr window,out Rect rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr window,IntPtr dc,uint flags);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr window,IntPtr after,int x,int y,int width,int height,uint flags);
    [DllImport("user32.dll")] public static extern bool RedrawWindow(IntPtr window,IntPtr update,IntPtr region,uint flags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window,int command);
    private delegate bool WindowCallback(IntPtr window,IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback,IntPtr parameter);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window,out uint process);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr window,System.Text.StringBuilder text,int count);
    public static IntPtr FindOwnWindow(int process) { return FindTitledWindow(process,"HexLab"); }
    private static IntPtr FindTitledWindow(int process,string label) {
        IntPtr found=IntPtr.Zero;
        EnumWindows((window,parameter)=>{
            uint owner; GetWindowThreadProcessId(window,out owner);
            if(owner==(uint)process) {
                var title=new System.Text.StringBuilder(512);
                GetWindowText(window,title,title.Capacity);
                if(title.ToString().IndexOf(label,StringComparison.Ordinal)>=0) { found=window; return false; }
            }
            return true;
        },IntPtr.Zero);
        return found;
    }
    [DllImport("user32.dll")] private static extern IntPtr GetMenu(IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr GetSubMenu(IntPtr menu,int position);
    [DllImport("user32.dll")] private static extern int GetMenuItemCount(IntPtr menu);
    [DllImport("user32.dll")] private static extern uint GetMenuItemID(IntPtr menu,int position);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetMenuString(IntPtr menu,uint item,System.Text.StringBuilder text,int count,uint flags);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr window,uint message,IntPtr first,IntPtr second);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent,WindowCallback callback,IntPtr parameter);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr window,System.Text.StringBuilder name,int count);
    [DllImport("user32.dll",EntryPoint="SendMessageTimeoutW",CharSet=CharSet.Unicode)] private static extern IntPtr SendText(IntPtr window,uint message,IntPtr first,string value,uint flags,uint timeout,out UIntPtr result);
    [DllImport("user32.dll",EntryPoint="SendMessageTimeoutW",CharSet=CharSet.Unicode)] private static extern IntPtr ReadText(IntPtr window,uint message,IntPtr first,System.Text.StringBuilder value,uint flags,uint timeout,out UIntPtr result);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr control);
    public static bool OpenJump(IntPtr window) {
        var root=GetMenu(window);
        for(int menu=0;menu<GetMenuItemCount(root);++menu) {
            var child=GetSubMenu(root,menu);
            for(int item=0;item<GetMenuItemCount(child);++item) {
                var label=new System.Text.StringBuilder(512);
                GetMenuString(child,(uint)item,label,label.Capacity,0x400);
                if(label.ToString().IndexOf("Jump",StringComparison.Ordinal)>=0)
                    return PostMessage(window,0x111,new IntPtr(GetMenuItemID(child,item)),IntPtr.Zero);
            }
        }
        return false;
    }
    public static bool SubmitJump(int process,string location) {
        var dialog=FindTitledWindow(process,"Jump to location");
        if(dialog==IntPtr.Zero) return false;
        IntPtr edit=IntPtr.Zero,accept=IntPtr.Zero;
        EnumChildWindows(dialog,(window,parameter)=>{
            var name=new System.Text.StringBuilder(128);GetClassName(window,name,name.Capacity);
            if(name.ToString()=="Edit") edit=window;
            if(name.ToString()=="Button") {
                var label=new System.Text.StringBuilder(128);GetWindowText(window,label,label.Capacity);
                if(label.ToString().Replace("&","")=="OK") accept=window;
            }
            return true;
        },IntPtr.Zero);
        if(edit==IntPtr.Zero || accept==IntPtr.Zero) return false;
        // Cross-process controls require WM_SETTEXT, not SetWindowText's caption path.
        UIntPtr result;
        if(SendText(edit,0xC,IntPtr.Zero,location,2,2000,out result)==IntPtr.Zero || result==UIntPtr.Zero) return false;
        var actual=new System.Text.StringBuilder(512);
        if(ReadText(edit,0xD,new IntPtr(actual.Capacity),actual,2,2000,out result)==IntPtr.Zero || actual.ToString()!=location)
            throw new InvalidOperationException("Own Jump control did not adopt the requested input");
        return PostMessage(dialog,0x111,new IntPtr(GetDlgCtrlID(accept)),accept);
    }
}
'@
function Capture-Window($Process, [string]$Name) {
    [void][HexLabInstalledWindow]::ShowWindow($Process.MainWindowHandle,4)
    $rect = New-Object HexLabInstalledWindow+Rect
    if (-not [HexLabInstalledWindow]::GetWindowRect($Process.MainWindowHandle,[ref]$rect)) { throw 'Cannot locate own application window' }
    $bitmap = New-Object Drawing.Bitmap ($rect.Right-$rect.Left),($rect.Bottom-$rect.Top),([Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $dc = $graphics.GetHdc()
        try {
            [void][HexLabInstalledWindow]::RedrawWindow($Process.MainWindowHandle,[IntPtr]::Zero,[IntPtr]::Zero,0x585)
            $printed = [HexLabInstalledWindow]::PrintWindow($Process.MainWindowHandle,$dc,0)
        }
        finally { $graphics.ReleaseHdc($dc) }
        if (-not $printed) { throw 'Cannot capture own installed application window' }
        $lit=0; $sampled=0
        for($y=0;$y -lt $bitmap.Height;$y+=16) {
            for($x=0;$x -lt $bitmap.Width;$x+=16) {
                $sampled++; $pixel=$bitmap.GetPixel($x,$y)
                if($pixel.R -gt 32 -or $pixel.G -gt 32 -or $pixel.B -gt 32) { $lit++ }
            }
        }
        if($lit -le $sampled/10) { throw 'Own-window capture is blank; no visual acceptance evidence was produced' }
        $bitmap.Save((Join-Path $artifact $Name),[Drawing.Imaging.ImageFormat]::Png)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
}
$process = Start-Process -FilePath (Join-Path $bin 'hexlab.exe') -ArgumentList ('"' + $fixture + '"') -WorkingDirectory $bin -PassThru -WindowStyle Hidden
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $loaded = $false
    $jumpSent=$false; $jumpFilled=$false
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) { throw "Installed application exited: $($process.ExitCode)" }
        if ($process.MainWindowHandle -eq [IntPtr]::Zero) {
            $own=[HexLabInstalledWindow]::FindOwnWindow($process.Id)
            if($own -ne [IntPtr]::Zero) { [void][HexLabInstalledWindow]::ShowWindow($own,4); $process.Refresh() }
        }
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) {
            if($NavigateTo -and $jumpSent -and -not $jumpFilled) { $jumpFilled=[HexLabInstalledWindow]::SubmitJump($process.Id,$NavigateTo) }
            $root = [Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
            # This pinned wx build exposes generic panes through UI Automation.
            # Its status bar is readable; native tab assertions live in the wx tests.
            $elements = $root.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
            foreach ($element in $elements) {
                if($NavigateTo -and -not $jumpSent -and $element.Current.Name.StartsWith('file:')) { $jumpSent=[HexLabInstalledWindow]::OpenJump($process.MainWindowHandle) }
                if ($element.Current.Name.StartsWith($expectedAddress) -and $element.Current.Name.Contains($Mode)) { $loaded=$true; break }
            }
        }
        if ($loaded) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $loaded) {
        Capture-Window $process 'load-diagnostic.png'
        $elements=$root.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
        $elements | Select-Object -First 100 | ForEach-Object { Write-Output ($_.Current.ControlType.ProgrammaticName + ': ' + $_.Current.Name) }
        throw 'Installed application did not reach its loaded status'
    }
    foreach ($name in @('hexlab_core.dll','hexlab_image.dll','hexlab_processors.dll','hexlab_loaders.dll','hexlab_analysis.dll','hexlab_database.dll','hexlab_workspace.dll','hexlab_sqlite3.dll')) {
        $module = @($process.Modules | Where-Object { $_.ModuleName -eq $name })
        if ($module.Count -ne 1 -or -not [IO.Path]::GetFullPath($module[0].FileName).StartsWith($bin + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw "Runtime did not resolve from installed bin: $name" }
        Write-Output "$name -> $($module[0].FileName)"
    }
    $wx = @($process.Modules | Where-Object { $_.ModuleName -like 'wx*.dll' })
    if ($wx.Count -lt 3) { throw 'Installed wx runtimes were not loaded' }
    foreach ($module in $wx) {
        if (-not [IO.Path]::GetFullPath($module.FileName).StartsWith($bin + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw "wx runtime loaded from another distribution: $($module.FileName)" }
    }
    [void][HexLabInstalledWindow]::SetWindowPos($process.MainWindowHandle,[IntPtr]::Zero,0,0,1200,800,6)
    Start-Sleep -Milliseconds 150
    Capture-Window $process ($capturePrefix+'-normal.png')
    [void][HexLabInstalledWindow]::SetWindowPos($process.MainWindowHandle,[IntPtr]::Zero,0,0,800,600,6)
    Start-Sleep -Milliseconds 150
    Capture-Window $process ($capturePrefix+'-compact.png')
    Write-Output "Installed application $Mode loaded status, runtime identities and own-window captures verified: $artifact"
} finally {
    if (-not $process.HasExited) {
        [void]$process.CloseMainWindow()
        if (-not $process.WaitForExit(5000)) { $process.Kill(); $process.WaitForExit() }
    }
}
