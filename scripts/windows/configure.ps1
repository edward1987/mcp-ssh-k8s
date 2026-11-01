[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Configure', 'Uninstall')][string]$Action = 'Configure',
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [string]$DataDir,
    [ValidateSet(0, 1)][int]$EnableService = 0,
    [ValidatePattern('^[A-Za-z0-9-]+$')][string]$ServiceName = 'McpSshK8s',
    [ValidateRange(1, 65535)][int]$AdminPort = 7777,
    [ValidateRange(1, 65535)][int]$McpPort = 7778,
    [string]$UserSid,
    [string]$ErrorFile
)
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Invoke-Wrapper([string]$Command) {
    & (Join-Path $InstallDir 'mcp-ssh-service.exe') $Command
    if ($LASTEXITCODE -ne 0) { throw "Windows service command failed: $Command (exit $LASTEXITCODE)." }
}

function Assert-DataDirectory {
    if (-not [IO.Path]::IsPathRooted($DataDir) -or $DataDir.StartsWith('\\')) {
        throw 'Choose an absolute folder on a local drive for the data.'
    }
    $script:DataDir = [IO.Path]::GetFullPath($DataDir).TrimEnd('\')
    $app = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    if ($DataDir -match '[%\r\n]' -or $DataDir.Length -le 3 -or $DataDir -eq $app -or $DataDir.StartsWith($app + '\', [StringComparison]::OrdinalIgnoreCase) -or $app.StartsWith($DataDir + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The data folder must be outside the application folder and cannot be a drive root or contain percent signs.'
    }
    $vault = Join-Path $DataDir 'vault.json'
    if (Test-Path -LiteralPath $vault) {
        $v = Get-Content -LiteralPath $vault -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($v.v -ne 1 -or $v.kdf.name -ne 'scrypt' -or -not $v.ct -or -not $v.nonce -or -not $v.tag) {
            throw 'The selected vault.json is not a supported encrypted MCP SSH vault. No files were changed.'
        }
    }
}

try {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($Action -eq 'Uninstall') {
        if ($service) {
            if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
            Invoke-Wrapper 'uninstall'
        }
        # Only remove installation metadata. Vault, audit, backups and logs are retained.
        $configFile = Join-Path $InstallDir 'install.json'
        if (Test-Path -LiteralPath $configFile) { Remove-Item -LiteralPath $configFile }
        exit 0
    }
    Assert-DataDirectory
    if ($Action -eq 'Prepare') {
        $wasRunning = $service -and $service.Status -eq 'Running'
        try {
            if ($service -and $service.Status -ne 'Stopped') {
                Stop-Service -Name $serviceName
                $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            }
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in $AdminPort, $McpPort })
            if ($listeners.Count) { throw "Ports $AdminPort/$McpPort are in use. Stop the old MCP SSH instance (Ctrl+C in its terminal), then retry. Your data has not been changed." }
            # Snapshot only persistent records. Python environments and downloaded binaries stay in place.
            if (Test-Path -LiteralPath (Join-Path $DataDir 'vault.json')) {
                $backup = Join-Path $DataDir ('backups\before-install-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
                New-Item -ItemType Directory -Path $backup -Force | Out-Null
                foreach ($name in @('vault.json', 'audit.jsonl')) {
                    $source = Join-Path $DataDir $name
                    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $backup $name) }
                }
                Write-Output "Backup: $backup"
            }
        } catch {
            if ($wasRunning) { Start-Service -Name $serviceName }
            throw
        }
        exit 0
    }

    $newDirectory = -not (Test-Path -LiteralPath $DataDir)
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    if ($newDirectory) {
        # ProgramData normally inherits read access for all users. Restrict new data folders.
        if (-not $UserSid) { $UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $UserSid) | Select-Object -Unique) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $DataDir -AclObject $acl
    }
    if ($EnableService -eq 1) {
        # Locale-independent SID for NT AUTHORITY\LocalService. Preserve existing folder ACLs.
        & icacls.exe $DataDir /grant '*S-1-5-19:(OI)(CI)M' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot grant LocalService access to the data folder.' }
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'logs') | Out-Null
    $escape = { param($s) [Security.SecurityElement]::Escape($s) }
    $dataXml = & $escape $DataDir
    $appXml = & $escape $InstallDir
    $displayName = 'MCP SSH K8s'
    if ($ServiceName -ne 'McpSshK8s') { $displayName += " ($ServiceName)" }
    $xml = @"
<service>
  <id>$serviceName</id>
  <name>$displayName</name>
  <description>Local SSH and Kubernetes MCP gateway. Unlock the vault at http://127.0.0.1:$AdminPort after each restart.</description>
  <executable>$appXml\runtime\node.exe</executable>
  <arguments>&quot;$appXml\dist\index.js&quot;</arguments>
  <workingdirectory>$appXml</workingdirectory>
  <env name="MCP_SSH_DATA" value="$dataXml" />
  <env name="ADMIN_PORT" value="$AdminPort" />
  <env name="MCP_PORT" value="$McpPort" />
  <env name="MCP_BIND" value="127.0.0.1" />
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <serviceaccount><domain>NT AUTHORITY</domain><user>LocalService</user></serviceaccount>
  <onfailure action="restart" delay="10 sec" />
  <stoptimeout>20 sec</stoptimeout>
  <logpath>$dataXml\logs</logpath>
  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>3</keepFiles></log>
</service>
"@
    $xmlFile = Join-Path $InstallDir 'mcp-ssh-service.xml'
    [IO.File]::WriteAllText($xmlFile, $xml, $utf8)
    $config = @{ schemaVersion = 1; dataDir = $DataDir; serviceEnabled = ($EnableService -eq 1); serviceName = $ServiceName; adminPort = $AdminPort; mcpPort = $McpPort } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $InstallDir 'install.json'), $config, $utf8)
    if ($service) {
        if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
        Invoke-Wrapper 'uninstall'
    }
    if ($EnableService -eq 1) {
        Invoke-Wrapper 'install'
        Invoke-Wrapper 'start'
        $ready = $false
        for ($i = 0; $i -lt 40; $i++) {
            try { $status = Invoke-RestMethod "http://127.0.0.1:$AdminPort/api/status" -TimeoutSec 2; $ready = $true; break } catch { Start-Sleep -Milliseconds 500 }
        }
        if (-not $ready) { throw "Service installed but the web interface did not start. Check $DataDir\logs and Services > MCP SSH K8s." }
    }
    Write-Output "Configured. Data folder: $DataDir; automatic Windows service: $($EnableService -eq 1)"
} catch {
    if ($ErrorFile) { [IO.File]::WriteAllText($ErrorFile, $_.Exception.Message, $utf8) }
    Write-Error $_.Exception.Message
    exit 1
}
