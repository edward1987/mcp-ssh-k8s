[CmdletBinding()]
param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$app = $PSScriptRoot
try {
    $config = Get-Content -LiteralPath (Join-Path $app 'install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $url = "http://127.0.0.1:$($config.adminPort)"
    $service = Get-Service -Name $config.serviceName -ErrorAction SilentlyContinue
    if ($config.serviceEnabled -and (-not $service -or $service.Status -ne 'Running')) {
        throw 'Serviciul MCP SSH K8s este oprit. Porneste-l din Services (services.msc) cu drepturi de administrator.'
    }
    $ready = $false
    try { $null = Invoke-RestMethod "$url/api/status" -TimeoutSec 2; $ready = $true } catch {}
    if (-not $ready -and -not $config.serviceEnabled) {
        # Child process inherits environment; installed settings take precedence over shell overrides.
        $env:MCP_SSH_DATA = $config.dataDir
        $env:ADMIN_PORT = [string]$config.adminPort; $env:MCP_PORT = [string]$config.mcpPort; $env:MCP_BIND = '127.0.0.1'
        $logs = Join-Path $config.dataDir 'logs'
        New-Item -ItemType Directory -Force -Path $logs | Out-Null
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $process = Start-Process -FilePath (Join-Path $app 'runtime\node.exe') -ArgumentList ('"' + (Join-Path $app 'dist\index.js') + '"') -WorkingDirectory $app -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logs "manual-$stamp.out.log") -RedirectStandardError (Join-Path $logs "manual-$stamp.err.log")
        for ($i = 0; $i -lt 40; $i++) {
            if ($process.HasExited) { throw "Aplicatia nu a pornit. Verifica logurile din $logs." }
            try { $null = Invoke-RestMethod "$url/api/status" -TimeoutSec 2; $ready = $true; break } catch { Start-Sleep -Milliseconds 250 }
        }
    }
    if (-not $ready) { throw 'Interfata MCP SSH nu raspunde. Verifica serviciul si logurile din folderul de date.' }
    if (-not $NoBrowser) { Start-Process $url }
} catch {
    if ($NoBrowser) { Write-Error $_.Exception.Message } else {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'MCP SSH K8s') | Out-Null
    }
    exit 1
}
