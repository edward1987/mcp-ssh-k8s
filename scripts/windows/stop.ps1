[CmdletBinding()]
param([switch]$Quiet)
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
$ErrorActionPreference = 'Stop'
try {
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.serviceEnabled) { throw 'Opreste serviciul MCP SSH K8s din Services (services.msc), cu drepturi de administrator.' }
    $node = Join-Path $PSScriptRoot 'runtime\node.exe'
    $entry = Join-Path $PSScriptRoot 'dist\index.js'
    Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.ExecutablePath -eq $node -and $_.CommandLine -and $_.CommandLine.Contains('"' + $entry + '"') } | ForEach-Object { Stop-Process -Id $_.ProcessId }
    # The application exit hook is not guaranteed on Windows forced termination.
    $tunnel = Join-Path $config.dataDir 'bin\tunnel-client-runtime.exe'
    Get-CimInstance Win32_Process -Filter "Name='tunnel-client-runtime.exe'" | Where-Object { $_.ExecutablePath -eq $tunnel } | ForEach-Object { Stop-Process -Id $_.ProcessId }
} catch {
    if ($Quiet) { Write-Error $_.Exception.Message } else {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'MCP SSH K8s') | Out-Null
    }
    exit 1
}
