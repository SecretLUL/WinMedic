#Requires -Version 7.0
<#
.SYNOPSIS
    Render assets/logo.svg into the icons the build embeds.

.DESCRIPTION
    `assets/logo.svg` is the only source of the logo. Two files are made from
    it and committed, because the build must not need anything beyond Rust and
    the MSVC tools:

    - `assets/icon.ico` - the executable's icon, which `build.rs` embeds with
      rc.exe and Explorer, the taskbar and the Start menu show. It holds every
      size Windows asks for at 100 % to 200 % scaling (16 to 64 px, and 256 px
      for large Explorer views), each rendered from the SVG itself rather than
      scaled down from a big bitmap, so the small ones stay sharp. Every image
      is stored as PNG, which rc.exe copies as is and Windows reads since Vista.
    - `assets/logo.png` - 256 px, the window icon `main.rs` hands to eframe.

    Run it after changing the SVG:

        ./scripts/render-icon.ps1

    Needs ImageMagick 7 (`magick`) with its librsvg delegate, which the Windows
    installer includes.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$assets = Join-Path $PSScriptRoot '..' 'assets'
$svg = Join-Path $assets 'logo.svg'
if (-not (Get-Command magick -ErrorAction SilentlyContinue)) {
    throw 'ImageMagick 7 (magick) is not on PATH.'
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$work = Join-Path ([System.IO.Path]::GetTempPath()) "winmedic-icon-$PID"
New-Item -ItemType Directory -Force $work | Out-Null

try {
    $pngs = foreach ($size in $sizes) {
        $out = Join-Path $work "$size.png"
        # The SVG is 256 px at 96 dpi. Render at eight times the target size
        # and scale down, which antialiases the edges evenly.
        & magick -background none -density (3 * $size) $svg -resize "${size}x${size}" `
            -depth 8 -strip "PNG32:$out"
        if ($LASTEXITCODE -ne 0) { throw "magick failed for $size px" }
        $out
    }

    Copy-Item (Join-Path $work '256.png') (Join-Path $assets 'logo.png') -Force

    # ICONDIR, one ICONDIRENTRY per image, then the PNG files themselves.
    $images = foreach ($png in $pngs) { , [System.IO.File]::ReadAllBytes($png) }
    $buffer = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($buffer)
    $writer.Write([UInt16] 0)
    $writer.Write([UInt16] 1)
    $writer.Write([UInt16] $images.Count)
    $offset = 6 + 16 * $images.Count
    for ($i = 0; $i -lt $images.Count; $i++) {
        # 0 in the directory means 256.
        $dimension = [byte] ($sizes[$i] % 256)
        $writer.Write($dimension)
        $writer.Write($dimension)
        $writer.Write([byte] 0)
        $writer.Write([byte] 0)
        $writer.Write([UInt16] 1)
        $writer.Write([UInt16] 32)
        $writer.Write([UInt32] $images[$i].Length)
        $writer.Write([UInt32] $offset)
        $offset += $images[$i].Length
    }
    foreach ($image in $images) { $writer.Write($image) }
    $writer.Flush()
    [System.IO.File]::WriteAllBytes((Join-Path $assets 'icon.ico'), $buffer.ToArray())

    Write-Host "Wrote assets/icon.ico ($($sizes -join ', ') px) and assets/logo.png (256 px)."
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
