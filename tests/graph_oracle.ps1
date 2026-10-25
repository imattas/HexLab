param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
$graph=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
if($graph.nodes.Count -ne 4 -or $graph.edges.Count -ne 4){throw 'Graph export topology mismatch'}
$expected='entry "quoted" \'+[char]10+[char]0x3b1
if(-not ($graph.nodes | Where-Object label -eq $expected)){throw 'Graph label Unicode/escaping mismatch'}
if(-not ($graph.nodes | Where-Object {$_.body_preview -contains 'ret'})){throw 'Actual return instruction missing from graph preview'}
if($graph.layout.positions.Count -ne 4 -or $graph.layout.routes.Count -ne 4){throw 'Graph layout export is incomplete'}
Add-Type -AssemblyName System.Drawing
$bitmap=New-Object System.Drawing.Bitmap 1200,800
$graphics=[System.Drawing.Graphics]::FromImage($bitmap)
$font=New-Object System.Drawing.Font 'Consolas',10
$pen=New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(90,110,130)),1.5
try {
    $graphics.Clear([System.Drawing.Color]::White)
    $bounds=$graph.layout.bounds
    $scale=[Math]::Min(1120/[Math]::Max(1,$bounds.width),720/[Math]::Max(1,$bounds.height))
    foreach($route in $graph.layout.routes){
        $points=@($route.points | ForEach-Object {New-Object System.Drawing.PointF ([float](40+($_.x-$bounds.x)*$scale)),([float](40+($_.y-$bounds.y)*$scale))})
        $graphics.DrawLines($pen,[System.Drawing.PointF[]]$points)
    }
    foreach($position in $graph.layout.positions){
        $node=$graph.nodes | Where-Object id -eq $position.node
        $x=[float](40+($position.x-$bounds.x)*$scale);$y=[float](40+($position.y-$bounds.y)*$scale)
        $width=[float]($position.width*$scale);$height=[float]($position.height*$scale)
        $graphics.FillRectangle([System.Drawing.Brushes]::AliceBlue,$x,$y,$width,$height)
        $graphics.DrawRectangle($pen,$x,$y,$width,$height)
        $text=$node.label+[char]10+($node.body_preview -join [char]10)
        $rectangle=New-Object System.Drawing.RectangleF ([float]($x+6)),([float]($y+4)),([float]($width-12)),([float]($height-8))
        $graphics.DrawString($text,$font,[System.Drawing.Brushes]::Black,$rectangle)
    }
    $bitmap.Save(([System.IO.Path]::ChangeExtension($Path,'png')),[System.Drawing.Imaging.ImageFormat]::Png)
} finally {$pen.Dispose();$font.Dispose();$graphics.Dispose();$bitmap.Dispose()}
