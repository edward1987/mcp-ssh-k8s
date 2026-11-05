[CmdletBinding()]
param([string]$IsccPath, [switch]$SkipTests)
# npm may launch Windows PowerShell from pwsh, which inherits pwsh's module paths.
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$cache = Join-Path $root '.release-cache'
$release = Join-Path $root 'release'
$stage = Join-Path $release 'payload'
$nodeVersion = '24.22.2'
$nodeHash = 'ca1bff5d8ead13c9f2ea404a176db46bd430704d5b5113734049fa365e7799e2'
$winswHash = '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da'

function Run([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}
function Download([string]$Url, [string]$Path, [string]$Hash) {
    if (-not (Test-Path -LiteralPath $Path)) { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) { throw "SHA256 mismatch: $Path. Delete this cached file and retry." }
}

Push-Location $root
try {
    if (-not $env:MCP_SSH_INTEGRITY_SIGNING_KEY) { throw 'A release requires the protected CI secret MCP_SSH_INTEGRITY_SIGNING_KEY (Ed25519 PEM). No unsigned installer will be built.' }
    $releaseSigningKey = $env:MCP_SSH_INTEGRITY_SIGNING_KEY
    Remove-Item Env:MCP_SSH_INTEGRITY_SIGNING_KEY
    $version = (Get-Content package.json -Raw | ConvertFrom-Json).version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'The release needs a stable semver version.' }
    if (-not $IsccPath) {
        foreach ($candidate in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 7\ISCC.exe")) {
            if (Test-Path -LiteralPath $candidate) { $IsccPath = $candidate; break }
        }
    }
    if (-not $IsccPath) { throw 'Install Inno Setup 6.3+ or pass -IsccPath to ISCC.exe.' }
    if (-not $SkipTests) { Run 'npm.cmd' @('test') }
    Run 'npm.cmd' @('run', 'build')
    New-Item -ItemType Directory -Force -Path $cache, $release | Out-Null
    # Resolve and verify the only recursive-delete target before removing a previous payload.
    $resolvedStage = [IO.Path]::GetFullPath($stage)
    if ($resolvedStage -ne (Join-Path $root 'release\payload') -or -not $resolvedStage.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staging path.' }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $resolvedStage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage | Out-Null

    $nodeArchive = Join-Path $cache "node-v$nodeVersion-win-x64.zip"
    Download "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-win-x64.zip" $nodeArchive $nodeHash
    $winsw = Join-Path $cache 'WinSW-x64.exe'
    Download 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' $winsw $winswHash
    $nodeDir = Join-Path $cache "node-v$nodeVersion-win-x64"
    if (-not (Test-Path -LiteralPath (Join-Path $nodeDir 'node.exe'))) { Expand-Archive -LiteralPath $nodeArchive -DestinationPath $cache -Force }
    New-Item -ItemType Directory -Path (Join-Path $stage 'runtime') | Out-Null
    Copy-Item -LiteralPath (Join-Path $nodeDir 'node.exe') -Destination (Join-Path $stage 'runtime\node.exe')
    Copy-Item -LiteralPath (Join-Path $nodeDir 'LICENSE') -Destination (Join-Path $stage 'runtime\NODE-LICENSE.txt')
    Copy-Item -LiteralPath $winsw -Destination (Join-Path $stage 'mcp-ssh-service.exe')
    # Explicit allowlist. The source data/ directory is NEVER part of the distributable.
    foreach ($name in @('dist', 'web', 'docs', 'README.md', 'LICENSE', 'package.json', 'package-lock.json')) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $stage -Recurse
    }
    New-Item -ItemType Directory -Path (Join-Path $stage 'scripts') | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'scripts\termius_dump.py') -Destination (Join-Path $stage 'scripts')
    foreach ($name in @('start.mjs', 'integrity.mjs')) { Copy-Item -LiteralPath (Join-Path $root "scripts\$name") -Destination (Join-Path $stage 'scripts') }
    foreach ($name in @('configure.ps1', 'launch.ps1', 'stop.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $stage }
    Push-Location $stage
    try { Run 'npm.cmd' @('ci', '--omit=dev', '--omit=optional', '--ignore-scripts', '--no-audit', '--no-fund') } finally { Pop-Location }
    $notices = @"
MCP SSH K8s $version - Windows x64
Node.js ${nodeVersion}: https://nodejs.org/ (license: runtime/NODE-LICENSE.txt)
WinSW 2.12.0: https://github.com/winsw/winsw (MIT)
WinSW Copyright (c) 2011-2020 Kohsuke Kawaguchi, Sun Microsystems, Inc., CloudBees, Inc., and other contributors.
WinSW is distributed under the MIT license reproduced in LICENSE.
JavaScript dependency licenses are included in node_modules next to each package.
The installer contains application code and public runtimes only. No user vault, logs or configuration are included.
"@
    [IO.File]::WriteAllText((Join-Path $stage 'THIRD-PARTY-NOTICES.txt'), $notices)

    # A small original terminal icon, generated locally without external assets.
    Add-Type -AssemblyName System.Drawing
    $bitmap = New-Object Drawing.Bitmap(64, 64)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.Clear([Drawing.Color]::FromArgb(15, 23, 42))
    $font = New-Object Drawing.Font('Consolas', 34, [Drawing.FontStyle]::Bold)
    $brush = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(94, 234, 212))
    $graphics.DrawString('>_', $font, $brush, -3, 5)
    $icon = [Drawing.Icon]::FromHandle($bitmap.GetHicon())
    $stream = [IO.File]::Create((Join-Path $stage 'app.ico'))
    try { $icon.Save($stream) } finally { $stream.Dispose(); $icon.Dispose(); $graphics.Dispose(); $font.Dispose(); $brush.Dispose(); $bitmap.Dispose() }
    try {
        $env:MCP_SSH_INTEGRITY_SIGNING_KEY = $releaseSigningKey
        Run 'node.exe' @((Join-Path $root 'scripts\integrity.mjs'), 'create', $stage, '--signed')
    } finally { Remove-Item Env:MCP_SSH_INTEGRITY_SIGNING_KEY -ErrorAction SilentlyContinue; $releaseSigningKey = $null }
    # The signing secret must not be inherited by the tested application or installer.
    Run 'node.exe' @((Join-Path $PSScriptRoot 'smoke-release.mjs'))
    if ((Test-Path -LiteralPath (Join-Path $stage 'data')) -or (Test-Path -LiteralPath (Join-Path $stage 'install.json'))) { throw 'Unexpected user data in payload.' }
    Run $IsccPath @("/DAppVersion=$version", "/DStageDir=$stage", "/DOutputDir=$release", (Join-Path $PSScriptRoot 'installer.iss'))
    $setup = Join-Path $release "mcp-ssh-k8s-$version-windows-x64-setup.exe"
    $sum = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + [IO.Path]::GetFileName($setup) + "`n"
    [IO.File]::WriteAllText((Join-Path $release 'SHA256SUMS.txt'), $sum, (New-Object Text.UTF8Encoding($false)))
    Copy-Item -LiteralPath (Join-Path $root "docs\releases\$version.md") -Destination (Join-Path $release 'RELEASE-NOTES.md')
    Write-Output "Release ready: $setup"
} finally { Pop-Location }
