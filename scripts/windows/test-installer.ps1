# Integration test for a disposable GitHub Actions Windows runner only.
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run this installation test only on a disposable GitHub Actions runner.' }
if (Get-Service McpSshK8s -ErrorAction SilentlyContinue) { throw 'Refusing to replace an existing service.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$version = (Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
$setup = Join-Path $root "release\mcp-ssh-k8s-$version-windows-x64-setup.exe"
$app = Join-Path $env:ProgramFiles 'MCP SSH K8s'
$data = Join-Path $env:ProgramData ('McpSshInstallerSmoke-' + [guid]::NewGuid().ToString('N'))
$logDir = Join-Path $root '.release-cache'
$vaultHash = $null
$uninstall = Join-Path $app 'unins000.exe'

function Install([string]$Tasks, [bool]$UseExistingRegistry = $false) {
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/NOICONS', "/TASKS=`"$Tasks`"", "/LOG=`"$logDir\installer-$Tasks.log`"")
    if (-not $UseExistingRegistry) { $arguments += "/DATADIR=`"$data`"" }
    $process = Start-Process -FilePath $setup -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Installer exited with $($process.ExitCode). See $logDir." }
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

try {
    Install 'service'
    $status = Invoke-RestMethod 'http://127.0.0.1:7777/api/status'
    Assert (-not $status.exists) 'A new install must not contain a user vault.'
    $service = Get-CimInstance Win32_Service -Filter "Name='McpSshK8s'"
    Assert ($service.State -eq 'Running' -and $service.StartMode -eq 'Auto' -and $service.StartName -match 'LocalService') 'Service must run automatically as LocalService.'
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $result = Invoke-RestMethod 'http://127.0.0.1:7777/api/setup' -Method Post -ContentType 'application/json' -Body '{"password":"installer test password 123"}' -WebSession $session
    $token = Invoke-RestMethod 'http://127.0.0.1:7777/api/tokens' -Method Post -ContentType 'application/json' -Body '{"name":"installer-ci"}' -WebSession $session -Headers @{ 'X-CSRF-Token' = $result.csrf }
    Assert ($token.token.StartsWith('mcp_')) 'Token creation failed.'
    $vault = Join-Path $data 'vault.json'
    $vaultHash = (Get-FileHash -LiteralPath $vault).Hash
    # Rerun the real installer: recover data location from registry and change to manual mode.
    Install '' $true
    $config = Get-Content (Join-Path $app 'install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($config.dataDir -eq $data -and -not $config.serviceEnabled) 'Upgrade must retain the folder and apply the selected task.'
    Assert (-not (Get-Service McpSshK8s -ErrorAction SilentlyContinue)) 'Switching to manual mode must remove the service.'
    Assert ((Get-FileHash -LiteralPath $vault).Hash -eq $vaultHash) 'Upgrade changed the existing vault.'
    $backups = @(Get-ChildItem (Join-Path $data 'backups') -Directory)
    Assert ($backups.Count -gt 0) 'Upgrade did not create a backup.'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'launch.ps1') -NoBrowser
    Assert ($LASTEXITCODE -eq 0) 'Manual launcher failed.'
    $status = Invoke-RestMethod 'http://127.0.0.1:7777/api/status'
    Assert ($status.exists -and -not $status.unlocked) 'Existing vault must start locked.'
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $null = Invoke-RestMethod 'http://127.0.0.1:7777/api/unlock' -Method Post -ContentType 'application/json' -Body '{"password":"installer test password 123"}' -WebSession $session
    $tokens = @(Invoke-RestMethod 'http://127.0.0.1:7777/api/tokens' -WebSession $session)
    Assert ($tokens[0].name -eq 'installer-ci') 'Original password/token did not survive installation.'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'stop.ps1') -Quiet
    Assert ($LASTEXITCODE -eq 0) 'Manual stop failed.'
    $process = Start-Process -FilePath $uninstall -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -WindowStyle Hidden -PassThru -Wait
    Assert ($process.ExitCode -eq 0) 'Uninstaller failed.'
    Assert ((Test-Path -LiteralPath $vault) -and (Get-FileHash -LiteralPath $vault).Hash -eq $vaultHash) 'Uninstall must preserve the vault.'
    Assert (-not (Get-Service McpSshK8s -ErrorAction SilentlyContinue)) 'Uninstall left a service behind.'
    Write-Output 'Installer integration passed: new install, automatic LocalService startup, reuse/backup on upgrade, switch to manual, password/token preservation, uninstall retains data.'
} finally {
    if (Test-Path -LiteralPath (Join-Path $app 'stop.ps1')) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'configure.ps1') -Action Uninstall -InstallDir $app
    }
    if (Test-Path -LiteralPath $uninstall) { Start-Process -FilePath $uninstall -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -WindowStyle Hidden -Wait }
}
