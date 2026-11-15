$ErrorActionPreference = 'Stop'

$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$exe = Join-Path $toolsDir 'winmedic.exe'

# WinMedic is one executable without an installer: the same file the releases
# page offers, checked against the SHA-256 published with it.
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileFullPath   = $exe
  url64bit       = 'https://github.com/SecretLUL/WinMedic/releases/download/v__VERSION__/winmedic-v__VERSION__.exe'
  checksum64     = '__SHA256__'
  checksumType64 = 'sha256'
}
Get-ChocolateyWebFile @packageArgs

# WinMedic is a window, so the `winmedic` shim starts it and returns instead of
# waiting until it is closed.
Set-Content -Path "$exe.gui" -Value '' -Encoding Ascii
