# Builds RamTrim.exe: merges the two scripts into one, embeds it in the C# launcher, compiles with the
# C# compiler that ships with Windows. Nothing is downloaded.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'src'
$obj = Join-Path $root 'build'
[void](New-Item -ItemType Directory -Force $obj)

$main = [IO.File]::ReadAllText((Join-Path $src 'RamTrim.ps1'), [Text.Encoding]::UTF8)
$sec = [IO.File]::ReadAllText((Join-Path $src 'Security.ps1'), [Text.Encoding]::UTF8)
$marker = ". (Join-Path `$PSScriptRoot 'Security.ps1')"
if (-not $main.Contains($marker)) { throw 'Security.ps1 include line not found in RamTrim.ps1' }
$combined = Join-Path $obj 'RamTrim.combined.ps1'
[IO.File]::WriteAllText($combined, $main.Replace($marker, $sec), (New-Object Text.UTF8Encoding($true)))

$csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$sma = (Get-ChildItem (Join-Path $env:windir 'Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation') -Recurse -Filter System.Management.Automation.dll | Select-Object -First 1).FullName
$out = Join-Path $root 'RamTrim.exe'
& $csc /nologo /target:winexe /platform:x64 /optimize+ "/out:$out" "/win32icon:$(Join-Path $root 'assets\RamTrim.ico')" `
    "/reference:$sma" /reference:System.Windows.Forms.dll "/resource:$combined,RamTrim.ps1" (Join-Path $src 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit code $LASTEXITCODE" }
'{0}  {1:N0} bytes' -f $out, (Get-Item $out).Length
