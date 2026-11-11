# Draws the RamTrim icon (yellow tile, black "RT") and writes assets\RamTrim.ico with 256/48/32/16 px images.
Add-Type -AssemblyName System.Drawing
$root = Split-Path $PSScriptRoot -Parent
[void](New-Item -ItemType Directory -Force (Join-Path $root 'assets'))
$images = foreach ($size in 256, 48, 32, 16) {
    $bmp = New-Object Drawing.Bitmap($size, $size)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
    $g.Clear([Drawing.Color]::FromArgb(18, 18, 18))
    $m = [int]($size * 0.08)
    $g.FillRectangle((New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(255, 214, 10))), $m, $m, $size - 2 * $m, $size - 2 * $m)
    $font = New-Object Drawing.Font('Segoe UI', [single]($size * 0.36), [Drawing.FontStyle]::Bold, [Drawing.GraphicsUnit]::Pixel)
    $fmt = New-Object Drawing.StringFormat; $fmt.Alignment = 'Center'; $fmt.LineAlignment = 'Center'
    $g.DrawString('RT', $font, [Drawing.Brushes]::Black, (New-Object Drawing.RectangleF(0, 0, $size, $size)), $fmt)
    $g.Dispose()
    $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    , @($size, $ms.ToArray())
}
$fs = [IO.File]::Create((Join-Path $root 'assets\RamTrim.ico'))
$w = New-Object IO.BinaryWriter($fs)
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$images.Count)
$offset = 6 + 16 * $images.Count
foreach ($img in $images) {
    $dim = if ($img[0] -ge 256) { 0 } else { $img[0] }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$img[1].Length); $w.Write([uint32]$offset)
    $offset += $img[1].Length
}
foreach ($img in $images) { $w.Write([byte[]]$img[1]) }
$w.Close()
'icon written'
