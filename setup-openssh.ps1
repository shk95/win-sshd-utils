#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet(
        'Menu',
        'Status',
        'InstallServer',
        'ConfigureService',
        'ConfigureFirewall',
        'InstallPublicKey',
        'NormalizeKeyAcl',
        'ConfigureAuthentication',
        'RestrictToUser',
        'RemoveUserRestriction',
        'ValidateConfiguration',
        'RestartSshd',
        'RecommendedSetup'
    )]
    [string] $Action = 'Menu',

    [string] $UserName = $env:USERNAME,

    [string] $PublicKeyFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$script:ConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
$script:ConfigBackupPath = "$($script:ConfigPath).setup-openssh.last-good.bak"
$script:ManagedBlockBegin = '# BEGIN managed by setup-openssh.ps1'
$script:ManagedBlockEnd = '# END managed by setup-openssh.ps1'
$script:AccessBackupPrefix = '# [setup-openssh.ps1 access-backup] '
$script:SupersededPrefix = '# [setup-openssh.ps1 superseded] '
$script:AdministratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$script:SystemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')

function Write-Result {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('OK', 'CHANGE', 'INFO', 'WARN')]
        [string] $Kind,

        [Parameter(Mandatory)]
        [string] $Message
    )

    Write-Host "[$Kind] $Message"
}

function Assert-CommandAvailable {
    param([Parameter(Mandatory)][string] $Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' is unavailable. This helper requires a supported Windows installation and an elevated PowerShell 7 session."
    }
}

function Assert-Environment {
    if (-not $IsWindows) {
        throw 'This helper can run only on Windows.'
    }

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "PowerShell 7 or newer is required. Current version: $($PSVersionTable.PSVersion)"
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole($script:AdministratorsSid)) {
        throw 'Administrator privileges are required. Start pwsh with Run as administrator.'
    }

    foreach ($command in @(
        'Get-WindowsCapability',
        'Add-WindowsCapability',
        'Get-Service',
        'Set-Service',
        'Start-Service',
        'Restart-Service',
        'Get-NetFirewallRule',
        'Get-NetFirewallPortFilter',
        'New-NetFirewallRule',
        'Set-NetFirewallRule',
        'Set-NetFirewallPortFilter',
        'Get-CimInstance',
        'Get-LocalGroupMember'
    )) {
        Assert-CommandAvailable -Name $command
    }
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [Parameter(Mandatory)][string[]] $ArgumentList,
        [Parameter(Mandatory)][string] $Description,
        [switch] $AllowFailure
    )

    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
    $exitCode = $LASTEXITCODE
    $result = [pscustomobject]@{
        ExitCode = $exitCode
        Output = ($output -join [Environment]::NewLine).Trim()
    }

    if (($exitCode -ne 0) -and -not $AllowFailure) {
        $detail = if ($result.Output) { "`n$($result.Output)" } else { '' }
        throw "$Description failed with exit code $exitCode.$detail"
    }

    return $result
}

function Get-OpenSshServerCapability {
    $capability = Get-WindowsCapability -Online |
        Where-Object Name -Like 'OpenSSH.Server*' |
        Select-Object -First 1

    return $capability
}

function Test-OpenSshServerInstalled {
    $capability = Get-OpenSshServerCapability
    return ($null -ne $capability -and $capability.State -eq 'Installed')
}

function Assert-OpenSshServerInstalled {
    if (-not (Test-OpenSshServerInstalled)) {
        throw "OpenSSH Server is not installed. Run this helper with -Action InstallServer first."
    }
}

function Ensure-OpenSshServer {
    $capability = Get-OpenSshServerCapability
    if ($null -eq $capability) {
        throw 'The OpenSSH.Server Windows capability is unavailable on this system.'
    }

    if ($capability.State -eq 'Installed') {
        Write-Result OK 'OpenSSH Server is already installed.'
        return $false
    }

    Write-Result CHANGE "Installing Windows capability $($capability.Name)..."
    $installResult = Add-WindowsCapability -Online -Name $capability.Name
    $capability = Get-OpenSshServerCapability
    if ($null -eq $capability -or $capability.State -ne 'Installed') {
        throw 'OpenSSH Server installation did not reach the Installed state.'
    }

    if ($installResult.RestartNeeded) {
        Write-Result WARN 'Windows reports that a restart is required before OpenSSH Server is fully available.'
    }

    $null = Get-SshdPath
    Write-Result OK 'OpenSSH Server installation verified.'
    return $true
}

function Get-SshdPath {
    $command = Get-Command -Name 'sshd.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $command) {
        return $command.Source
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($env:WINDIR) {
        $candidates.Add((Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'))
    }
    if ($env:ProgramFiles) {
        $candidates.Add((Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))
    }

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'sshd'" -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.PathName) {
        $servicePath = if ($service.PathName -match '^\s*"([^"]+)"') {
            $Matches[1]
        }
        else {
            ($service.PathName -split '\s+')[0]
        }
        $candidates.Add([Environment]::ExpandEnvironmentVariables($servicePath))
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw 'sshd.exe could not be located after OpenSSH Server installation.'
}

function Get-SshdServiceInfo {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name = 'sshd'" -ErrorAction SilentlyContinue
}

function Ensure-SshdService {
    Assert-OpenSshServerInstalled
    $serviceInfo = Get-SshdServiceInfo
    if ($null -eq $serviceInfo) {
        throw "The 'sshd' service does not exist after OpenSSH Server installation. A Windows restart might be required."
    }

    $changed = $false
    if ($serviceInfo.StartMode -ne 'Auto') {
        Set-Service -Name sshd -StartupType Automatic
        Write-Result CHANGE 'sshd startup type -> Automatic'
        $changed = $true
    }
    else {
        Write-Result OK 'sshd startup type is Automatic.'
    }

    $service = Get-Service -Name sshd
    if ($service.Status -ne 'Running') {
        if (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf) {
            $null = Assert-SshdConfigurationValid
        }
        Start-Service -Name sshd
        Write-Result CHANGE 'Started the sshd service.'
        $changed = $true
    }
    else {
        Write-Result OK 'sshd is already running.'
    }

    if (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf) {
        $null = Assert-SshdConfigurationValid
        Write-Result OK 'sshd_config validation passed.'
    }

    return $changed
}

function Ensure-SshdInitialized {
    Assert-OpenSshServerInstalled
    $sshdPath = Get-SshdPath
    $configDirectory = Split-Path -Parent $script:ConfigPath
    $configExists = Test-Path -LiteralPath $script:ConfigPath -PathType Leaf

    if ($configExists) {
        $hostKeys = @(Get-ChildItem -LiteralPath $configDirectory -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
        if ($hostKeys.Count -gt 0) {
            return
        }

        $sshKeygenPath = Join-Path (Split-Path -Parent $sshdPath) 'ssh-keygen.exe'
        if (-not (Test-Path -LiteralPath $sshKeygenPath -PathType Leaf)) {
            throw "No OpenSSH host keys exist and ssh-keygen.exe could not be found at $sshKeygenPath"
        }
        $null = Invoke-NativeCommand `
            -FilePath $sshKeygenPath `
            -ArgumentList @('-A') `
            -Description 'OpenSSH host-key generation'
        $hostKeys = @(Get-ChildItem -LiteralPath $configDirectory -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
        if ($hostKeys.Count -eq 0) {
            throw 'ssh-keygen -A completed but no OpenSSH host keys were found.'
        }
        Write-Result CHANGE 'Generated missing OpenSSH host keys.'
        return
    }

    Write-Result INFO 'Starting sshd once so Windows can generate its default configuration and host keys.'
    $null = Ensure-SshdService
    if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        throw "sshd did not generate the expected configuration file: $($script:ConfigPath)"
    }
}

function Test-FirewallRuleAllowsSsh {
    param([Parameter(Mandatory)] $Rule)

    if ($Rule.Enabled.ToString() -ne 'True' -or
        $Rule.Direction.ToString() -ne 'Inbound' -or
        $Rule.Action.ToString() -ne 'Allow') {
        return $false
    }

    foreach ($filter in @($Rule | Get-NetFirewallPortFilter)) {
        $ports = @($filter.LocalPort | ForEach-Object { $_.ToString() })
        if (($filter.Protocol -in @('TCP', '6')) -and ('22' -in $ports)) {
            return $true
        }
    }

    return $false
}

function Get-EquivalentSshFirewallRule {
    $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
    foreach ($rule in @($rules)) {
        if (Test-FirewallRuleAllowsSsh -Rule $rule) {
            return $rule
        }
    }
    return $null
}

function Ensure-SshFirewallRule {
    Assert-OpenSshServerInstalled
    $ruleName = 'OpenSSH-Server-In-TCP'
    $standardRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $standardRule) {
        if (Test-FirewallRuleAllowsSsh -Rule $standardRule) {
            Write-Result OK "Firewall rule '$ruleName' already allows inbound TCP 22."
            return $false
        }

        $equivalentRule = Get-EquivalentSshFirewallRule
        if ($null -ne $equivalentRule) {
            Write-Result OK "Existing firewall rule '$($equivalentRule.DisplayName)' already allows inbound TCP 22; the inactive or mismatched standard rule was left unchanged."
            return $false
        }

        Set-NetFirewallRule -Name $ruleName -Enabled True -Direction Inbound -Action Allow
        Get-NetFirewallRule -Name $ruleName |
            Get-NetFirewallPortFilter |
            Set-NetFirewallPortFilter -Protocol TCP -LocalPort 22
        Write-Result CHANGE "Normalized firewall rule '$ruleName' for inbound TCP 22."
        return $true
    }

    $equivalentRule = Get-EquivalentSshFirewallRule
    if ($null -ne $equivalentRule) {
        Write-Result OK "Existing firewall rule '$($equivalentRule.DisplayName)' already allows inbound TCP 22."
        return $false
    }

    New-NetFirewallRule `
        -Name $ruleName `
        -DisplayName 'OpenSSH Server (sshd)' `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -Action Allow `
        -LocalPort 22 | Out-Null
    Write-Result CHANGE "Created firewall rule '$ruleName' for inbound TCP 22."
    return $true
}

function Resolve-TargetUser {
    param([Parameter(Mandatory)][string] $Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'A target user name is required.'
    }

    $candidateNames = [System.Collections.Generic.List[string]]::new()
    if ($Name -match '[\\@]') {
        $candidateNames.Add($Name)
    }
    else {
        $candidateNames.Add("$env:COMPUTERNAME\$Name")
        $candidateNames.Add($Name)
    }

    $sid = $null
    $accountName = $null
    foreach ($candidateName in $candidateNames) {
        try {
            $account = [System.Security.Principal.NTAccount]::new($candidateName)
            $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
            $accountName = $sid.Translate([System.Security.Principal.NTAccount]).Value
            break
        }
        catch [System.Security.Principal.IdentityNotMappedException] {
            continue
        }
    }

    if ($null -eq $sid) {
        throw "Windows account '$Name' could not be resolved."
    }

    $profilePath = $null
    $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID = '$($sid.Value)'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $profile -and $profile.LocalPath) {
        $profilePath = $profile.LocalPath
    }
    else {
        $profileRegistryPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($sid.Value)"
        if (Test-Path -LiteralPath $profileRegistryPath) {
            $profilePath = [Environment]::ExpandEnvironmentVariables(
                (Get-ItemProperty -LiteralPath $profileRegistryPath -Name ProfileImagePath).ProfileImagePath
            )
        }
    }

    $leafName = ($accountName -split '\\')[-1]
    $sshdUserName = $accountName.ToLowerInvariant()
    if ($accountName.StartsWith("$env:COMPUTERNAME\", [System.StringComparison]::OrdinalIgnoreCase)) {
        $sshdUserName = $leafName.ToLowerInvariant()
    }

    $directAdministrator = $false
    try {
        $directAdministrator = [bool](Get-LocalGroupMember -SID $script:AdministratorsSid -ErrorAction Stop |
            Where-Object { $null -ne $_.SID -and $_.SID.Value -eq $sid.Value } |
            Select-Object -First 1)
    }
    catch {
        Write-Result WARN "Could not enumerate direct Administrators membership: $($_.Exception.Message)"
    }

    if ($sid.Value -like 'S-1-12-1-*') {
        throw "Microsoft Entra account '$accountName' is not supported for Windows OpenSSH public-key authentication."
    }

    return [pscustomobject]@{
        InputName = $Name
        AccountName = $accountName
        SshdUserName = $sshdUserName
        Sid = $sid
        ProfilePath = $profilePath
        DirectAdministrator = $directAdministrator
    }
}

function Get-PublicKeyInfo {
    param([Parameter(Mandatory)][string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'A public-key file is required for this action. Supply -PublicKeyFile or enter it in the menu.'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Public-key file does not exist: $Path"
    }

    $lines = @(Get-Content -LiteralPath $Path | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#')
    })
    if ($lines.Count -ne 1) {
        throw "Public-key file must contain exactly one nonempty, non-comment key line. Found: $($lines.Count)"
    }

    $line = $lines[0].Trim()
    $keyTypePattern = '(?:ssh-(?:rsa|ed25519)(?:-cert-v01@openssh\.com)?|ecdsa-sha2-nistp(?:256|384|521)(?:-cert-v01@openssh\.com)?|sk-ssh-ed25519(?:-cert-v01)?@openssh\.com|sk-ecdsa-sha2-nistp256(?:-cert-v01)?@openssh\.com)'
    if ($line -notmatch "^(?<Type>$keyTypePattern)\s+(?<Blob>[A-Za-z0-9+/]+={0,3})(?:\s+.*)?$") {
        throw 'The supplied file does not superficially resemble a supported OpenSSH public key.'
    }
    $keyType = $Matches.Type
    $keyBlob = $Matches.Blob

    try {
        $decoded = [Convert]::FromBase64String($keyBlob)
    }
    catch {
        throw 'The public-key base64 payload is invalid.'
    }
    if ($decoded.Length -lt 16) {
        throw 'The public-key payload is unexpectedly short.'
    }

    return [pscustomobject]@{
        Line = $line
        Type = $keyType
        Blob = $keyBlob
        Identity = "$keyType $keyBlob"
        SourcePath = (Resolve-Path -LiteralPath $Path).Path
    }
}

function Get-KeyIdentityFromAuthorizedKeyLine {
    param([Parameter(Mandatory)][string] $Line)

    $keyTypePattern = '(?:ssh-(?:rsa|ed25519)(?:-cert-v01@openssh\.com)?|ecdsa-sha2-nistp(?:256|384|521)(?:-cert-v01@openssh\.com)?|sk-ssh-ed25519(?:-cert-v01)?@openssh\.com|sk-ecdsa-sha2-nistp256(?:-cert-v01)?@openssh\.com)'
    if ($Line -match "(?:^|\s)(?<Type>$keyTypePattern)\s+(?<Blob>[A-Za-z0-9+/]+={0,3})(?:\s|$)") {
        return "$($Matches.Type) $($Matches.Blob)"
    }
    return $null
}

function Get-EffectiveSshdSettings {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [string] $ConfigPath = $script:ConfigPath
    )

    $sshdPath = Get-SshdPath
    $connection = "user=$($TargetUser.SshdUserName),host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22"
    $result = Invoke-NativeCommand `
        -FilePath $sshdPath `
        -ArgumentList @('-T', '-f', $ConfigPath, '-C', $connection) `
        -Description "Effective sshd configuration check for $($TargetUser.AccountName)"

    $settings = @{}
    foreach ($line in ($result.Output -split '\r?\n')) {
        if ($line -match '^\s*(?<Name>\S+)\s+(?<Value>.*)$') {
            $settings[$Matches.Name.ToLowerInvariant()] = $Matches.Value.Trim()
        }
    }
    return $settings
}

function Resolve-AuthorizedKeysPath {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)][string] $ConfiguredPath
    )

    $firstPath = if ($ConfiguredPath.StartsWith('"')) {
        if ($ConfiguredPath -notmatch '^"(?<Path>[^"]+)"') {
            throw "Could not parse AuthorizedKeysFile value: $ConfiguredPath"
        }
        $Matches.Path
    }
    else {
        ($ConfiguredPath -split '\s+')[0]
    }
    if ($firstPath.Equals('none', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The effective AuthorizedKeysFile is disabled (none); there is no destination for a public key.'
    }

    $expanded = $firstPath.Replace(
        '__PROGRAMDATA__',
        $env:ProgramData,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    $expanded = [Environment]::ExpandEnvironmentVariables($expanded)
    $expanded = $expanded.Replace('%u', $TargetUser.SshdUserName)

    if ($expanded.Contains('%h')) {
        if (-not $TargetUser.ProfilePath) {
            throw "The effective AuthorizedKeysFile uses %h, but no local profile was found for $($TargetUser.AccountName)."
        }
        $expanded = $expanded.Replace('%h', $TargetUser.ProfilePath)
    }
    if ($expanded -match '%[A-Za-z%]') {
        throw "AuthorizedKeysFile uses a token that this helper cannot safely resolve: $ConfiguredPath"
    }

    $expanded = $expanded.Replace('/', '\')
    if (-not [System.IO.Path]::IsPathRooted($expanded)) {
        if (-not $TargetUser.ProfilePath) {
            throw "A profile directory is required to resolve relative AuthorizedKeysFile '$ConfiguredPath'."
        }
        $expanded = Join-Path $TargetUser.ProfilePath $expanded
    }

    return [System.IO.Path]::GetFullPath($expanded)
}

function Get-AuthorizedKeysContext {
    param([Parameter(Mandatory)] $TargetUser)

    Ensure-SshdInitialized
    $settings = Get-EffectiveSshdSettings -TargetUser $TargetUser
    if (-not $settings.ContainsKey('authorizedkeysfile')) {
        throw 'sshd did not report an effective AuthorizedKeysFile value.'
    }

    $path = Resolve-AuthorizedKeysPath -TargetUser $TargetUser -ConfiguredPath $settings.authorizedkeysfile
    $administratorPath = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $usesAdministratorFile = $path.Equals(
        [System.IO.Path]::GetFullPath($administratorPath),
        [System.StringComparison]::OrdinalIgnoreCase
    )

    return [pscustomobject]@{
        Path = $path
        UsesAdministratorFile = $usesAdministratorFile
        EffectiveValue = $settings.authorizedkeysfile
        EffectiveSettings = $settings
    }
}

function New-DesiredFileAcl {
    param(
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier] $OwnerSid,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier[]] $AllowedSids
    )

    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($OwnerSid)
    $acl.SetGroup($script:AdministratorsSid)
    foreach ($sid in $AllowedSids) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function New-DesiredDirectoryAcl {
    param(
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier] $OwnerSid,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier[]] $AllowedSids
    )

    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($OwnerSid)
    $acl.SetGroup($script:AdministratorsSid)
    foreach ($sid in $AllowedSids) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Set-AclIfNeeded {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemSecurity] $DesiredAcl
    )

    $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Group, Access'
    $currentAcl = Get-Acl -LiteralPath $Path
    $currentSddl = $currentAcl.GetSecurityDescriptorSddlForm($sections)
    $desiredSddl = $DesiredAcl.GetSecurityDescriptorSddlForm($sections)
    if ($currentSddl -eq $desiredSddl) {
        return $false
    }

    Set-Acl -LiteralPath $Path -AclObject $DesiredAcl
    return $true
}

function Test-AclMatches {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemSecurity] $DesiredAcl
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Group, Access'
    $currentAcl = Get-Acl -LiteralPath $Path
    return (
        $currentAcl.GetSecurityDescriptorSddlForm($sections) -eq
        $DesiredAcl.GetSecurityDescriptorSddlForm($sections)
    )
}

function Get-AuthorizedKeysAclStatus {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)] $Context
    )

    if (-not (Test-Path -LiteralPath $Context.Path -PathType Leaf)) {
        return 'Missing'
    }

    if ($Context.UsesAdministratorFile) {
        $desiredFileAcl = New-DesiredFileAcl `
            -OwnerSid $script:AdministratorsSid `
            -AllowedSids @($script:SystemSid, $script:AdministratorsSid)
        if (Test-AclMatches -Path $Context.Path -DesiredAcl $desiredFileAcl) {
            return 'Correct'
        }
        return 'Needs normalization'
    }

    if (-not $TargetUser.ProfilePath) {
        return 'Unknown (profile unavailable)'
    }

    $allowedSids = @($TargetUser.Sid, $script:SystemSid, $script:AdministratorsSid)
    $desiredFileAcl = New-DesiredFileAcl -OwnerSid $TargetUser.Sid -AllowedSids $allowedSids
    if (-not (Test-AclMatches -Path $Context.Path -DesiredAcl $desiredFileAcl)) {
        return 'Needs normalization'
    }

    $expectedSshDirectory = [System.IO.Path]::GetFullPath((Join-Path $TargetUser.ProfilePath '.ssh'))
    $actualDirectory = [System.IO.Path]::GetFullPath((Split-Path -Parent $Context.Path))
    if ($actualDirectory.Equals($expectedSshDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
        $desiredDirectoryAcl = New-DesiredDirectoryAcl -OwnerSid $TargetUser.Sid -AllowedSids $allowedSids
        if (-not (Test-AclMatches -Path $actualDirectory -DesiredAcl $desiredDirectoryAcl)) {
            return 'Needs normalization'
        }
    }

    return 'Correct'
}

function Ensure-AuthorizedKeysAcl {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)] $Context
    )

    $filePath = $Context.Path
    $parentPath = Split-Path -Parent $filePath
    if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
        Write-Result CHANGE "Created directory $parentPath"
    }

    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        [System.IO.File]::WriteAllText($filePath, '', [System.Text.UTF8Encoding]::new($false))
        Write-Result CHANGE "Created $filePath"
    }

    $changed = $false
    if ($Context.UsesAdministratorFile) {
        $desiredFileAcl = New-DesiredFileAcl `
            -OwnerSid $script:AdministratorsSid `
            -AllowedSids @($script:SystemSid, $script:AdministratorsSid)
        if (Set-AclIfNeeded -Path $filePath -DesiredAcl $desiredFileAcl) {
            Write-Result CHANGE 'Normalized administrators_authorized_keys ACL.'
            $changed = $true
        }
        else {
            Write-Result OK 'administrators_authorized_keys ACL is already correct.'
        }
        return $changed
    }

    if (-not $TargetUser.ProfilePath) {
        throw "No profile directory was found for $($TargetUser.AccountName); ordinary-user key ACLs cannot be configured."
    }

    $allowedSids = @($TargetUser.Sid, $script:SystemSid, $script:AdministratorsSid)
    $expectedSshDirectory = Join-Path $TargetUser.ProfilePath '.ssh'
    if ($parentPath.Equals(
        [System.IO.Path]::GetFullPath($expectedSshDirectory),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        $desiredDirectoryAcl = New-DesiredDirectoryAcl -OwnerSid $TargetUser.Sid -AllowedSids $allowedSids
        if (Set-AclIfNeeded -Path $parentPath -DesiredAcl $desiredDirectoryAcl) {
            Write-Result CHANGE "Normalized ACL on $parentPath"
            $changed = $true
        }
        else {
            Write-Result OK "ACL on $parentPath is already correct."
        }
    }
    else {
        Write-Result WARN "AuthorizedKeysFile uses a custom directory; only the file ACL will be normalized: $parentPath"
    }

    $desiredFileAcl = New-DesiredFileAcl -OwnerSid $TargetUser.Sid -AllowedSids $allowedSids
    if (Set-AclIfNeeded -Path $filePath -DesiredAcl $desiredFileAcl) {
        Write-Result CHANGE "Normalized ACL on $filePath"
        $changed = $true
    }
    else {
        Write-Result OK "ACL on $filePath is already correct."
    }

    return $changed
}

function Test-PublicKeyInstalled {
    param(
        [Parameter(Mandatory)] $KeyInfo,
        [Parameter(Mandatory)][string] $AuthorizedKeysPath
    )

    if (-not (Test-Path -LiteralPath $AuthorizedKeysPath -PathType Leaf)) {
        return $false
    }

    foreach ($line in Get-Content -LiteralPath $AuthorizedKeysPath) {
        $identity = Get-KeyIdentityFromAuthorizedKeyLine -Line $line
        if ($identity -eq $KeyInfo.Identity) {
            return $true
        }
    }
    return $false
}

function Add-PublicKeyLine {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Line
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    $needsLeadingNewline = $false
    $fileInfo = Get-Item -LiteralPath $Path
    if ($fileInfo.Length -gt 0) {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            if ($stream.Length -ge 2) {
                $firstByte = $stream.ReadByte()
                $secondByte = $stream.ReadByte()
                if (($firstByte -eq 0xFF -and $secondByte -eq 0xFE) -or
                    ($firstByte -eq 0xFE -and $secondByte -eq 0xFF)) {
                    throw "Existing authorized_keys file is UTF-16. Convert it to UTF-8 before adding a key: $Path"
                }
            }
            $null = $stream.Seek(-1, [System.IO.SeekOrigin]::End)
            $lastByte = $stream.ReadByte()
            $needsLeadingNewline = $lastByte -notin @(10, 13)
        }
        finally {
            $stream.Dispose()
        }
    }

    $prefix = if ($needsLeadingNewline) { "`r`n" } else { '' }
    [System.IO.File]::AppendAllText($Path, "$prefix$Line`r`n", $encoding)
}

function Install-PublicKey {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)] $KeyInfo
    )

    Assert-OpenSshServerInstalled
    $context = Get-AuthorizedKeysContext -TargetUser $TargetUser
    $null = Ensure-AuthorizedKeysAcl -TargetUser $TargetUser -Context $context

    if (Test-PublicKeyInstalled -KeyInfo $KeyInfo -AuthorizedKeysPath $context.Path) {
        Write-Result OK "Public key is already installed in $($context.Path)"
        return [pscustomobject]@{ Changed = $false; Context = $context }
    }

    Add-PublicKeyLine -Path $context.Path -Line $KeyInfo.Line
    $null = Ensure-AuthorizedKeysAcl -TargetUser $TargetUser -Context $context
    if (-not (Test-PublicKeyInstalled -KeyInfo $KeyInfo -AuthorizedKeysPath $context.Path)) {
        throw "The public key could not be verified after writing $($context.Path)."
    }

    Write-Result CHANGE "Added public key for $($TargetUser.AccountName)."
    if ($context.UsesAdministratorFile) {
        Write-Result WARN 'This is the Windows default shared authorized-keys file for administrator accounts.'
    }
    return [pscustomobject]@{ Changed = $true; Context = $context }
}

function Test-SshdConfiguration {
    param([string] $ConfigPath = $script:ConfigPath)

    $sshdPath = Get-SshdPath
    $result = Invoke-NativeCommand `
        -FilePath $sshdPath `
        -ArgumentList @('-t', '-f', $ConfigPath) `
        -Description "Validation of $ConfigPath" `
        -AllowFailure

    return [pscustomobject]@{
        Passed = ($result.ExitCode -eq 0)
        Output = $result.Output
        ExitCode = $result.ExitCode
    }
}

function Assert-SshdConfigurationValid {
    param([string] $ConfigPath = $script:ConfigPath)

    $result = Test-SshdConfiguration -ConfigPath $ConfigPath
    if (-not $result.Passed) {
        $detail = if ($result.Output) { "`n$($result.Output)" } else { '' }
        throw "Failed to validate $ConfigPath (exit code $($result.ExitCode)).$detail"
    }
    return $result
}

function Get-ManagedConfigurationText {
    param(
        [Parameter(Mandatory)][string] $CurrentText,
        [ValidateSet('Preserve', 'Enable', 'Disable')]
        [string] $AccessMode = 'Preserve',
        [string] $RestrictedUser
    )

    if ($AccessMode -eq 'Enable' -and [string]::IsNullOrWhiteSpace($RestrictedUser)) {
        throw 'RestrictedUser is required when enabling the user restriction.'
    }

    $lines = @($CurrentText -split '\r?\n')
    $withoutManagedBlock = [System.Collections.Generic.List[string]]::new()
    $insideManagedBlock = $false
    $managedAllowUsers = $null
    $skipBlankAfterBlock = $false

    foreach ($line in $lines) {
        if ($line.Trim() -eq $script:ManagedBlockBegin) {
            if ($insideManagedBlock) {
                throw 'Nested setup-openssh.ps1 managed blocks were found in sshd_config.'
            }
            $insideManagedBlock = $true
            continue
        }
        if ($insideManagedBlock) {
            if ($line.Trim() -eq $script:ManagedBlockEnd) {
                $insideManagedBlock = $false
                $skipBlankAfterBlock = $true
                continue
            }
            if ($line -match '^\s*AllowUsers\s+(?<Value>.+?)\s*$') {
                $managedAllowUsers = $Matches.Value
            }
            continue
        }
        if ($skipBlankAfterBlock -and [string]::IsNullOrWhiteSpace($line)) {
            $skipBlankAfterBlock = $false
            continue
        }
        $skipBlankAfterBlock = $false
        $withoutManagedBlock.Add($line)
    }
    if ($insideManagedBlock) {
        throw 'The setup-openssh.ps1 managed block has no END marker.'
    }

    $effectiveAllowUsers = switch ($AccessMode) {
        'Enable' { $RestrictedUser.ToLowerInvariant() }
        'Disable' { $null }
        default { $managedAllowUsers }
    }

    $processed = [System.Collections.Generic.List[string]]::new()
    $insideMatch = $false
    $expected = @{
        'pubkeyauthentication' = 'yes'
        'passwordauthentication' = 'no'
        'permitemptypasswords' = 'no'
    }

    for ($index = 0; $index -lt $withoutManagedBlock.Count; $index++) {
        $line = $withoutManagedBlock[$index]
        $lineNumber = $index + 1
        if ($line -match '^\s*Match(?:\s|$)') {
            $insideMatch = $true
        }

        if ($insideMatch) {
            if ($line -match '^\s*(?<Name>PubkeyAuthentication|PasswordAuthentication|PermitEmptyPasswords)\s+(?<Value>\S+)') {
                $name = $Matches.Name.ToLowerInvariant()
                $value = $Matches.Value.ToLowerInvariant()
                if ($value -ne $expected[$name]) {
                    throw "Conflicting '$($Matches.Name) $($Matches.Value)' inside a Match section near line $lineNumber. The helper will not rewrite conditional policy."
                }
            }
            $processed.Add($line)
            continue
        }

        if ($line -match '^\s*(PubkeyAuthentication|PasswordAuthentication|PermitEmptyPasswords)\s+') {
            $processed.Add("$($script:SupersededPrefix)$line")
            continue
        }

        if ($AccessMode -eq 'Enable' -and $line -match '^\s*AllowUsers\s+') {
            $processed.Add("$($script:AccessBackupPrefix)$line")
            continue
        }

        if ($AccessMode -eq 'Disable' -and $line.StartsWith($script:AccessBackupPrefix, [System.StringComparison]::Ordinal)) {
            $processed.Add($line.Substring($script:AccessBackupPrefix.Length))
            continue
        }

        $processed.Add($line)
    }

    $managedLines = [System.Collections.Generic.List[string]]::new()
    $managedLines.Add($script:ManagedBlockBegin)
    $managedLines.Add('PubkeyAuthentication yes')
    $managedLines.Add('PasswordAuthentication no')
    $managedLines.Add('PermitEmptyPasswords no')
    if ($effectiveAllowUsers) {
        $managedLines.Add("AllowUsers $effectiveAllowUsers")
    }
    $managedLines.Add($script:ManagedBlockEnd)

    while ($processed.Count -gt 0 -and [string]::IsNullOrWhiteSpace($processed[0])) {
        $processed.RemoveAt(0)
    }
    while ($processed.Count -gt 0 -and [string]::IsNullOrWhiteSpace($processed[$processed.Count - 1])) {
        $processed.RemoveAt($processed.Count - 1)
    }

    $resultLines = @($managedLines) + @('') + @($processed)
    return (($resultLines -join "`r`n") + "`r`n")
}

function Set-SshdManagedConfiguration {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [ValidateSet('Preserve', 'Enable', 'Disable')]
        [string] $AccessMode = 'Preserve'
    )

    Ensure-SshdInitialized
    if ($AccessMode -eq 'Enable' -and $TargetUser.SshdUserName -match '[\s#*?!\[\]"]') {
        throw "AllowUsers restriction is not supported for an account name containing whitespace or SSH pattern metacharacters: $($TargetUser.SshdUserName)"
    }
    $currentText = [System.IO.File]::ReadAllText($script:ConfigPath)
    $candidateText = Get-ManagedConfigurationText `
        -CurrentText $currentText `
        -AccessMode $AccessMode `
        -RestrictedUser $TargetUser.SshdUserName

    if ($candidateText -ceq $currentText) {
        Write-Result OK 'sshd_config already contains the desired managed policy.'
        return $false
    }

    $configDirectory = Split-Path -Parent $script:ConfigPath
    $candidatePath = Join-Path $configDirectory ("sshd_config.setup-openssh.{0}.tmp" -f [Guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($candidatePath, $candidateText, [System.Text.UTF8Encoding]::new($false))
        Set-Acl -LiteralPath $candidatePath -AclObject (Get-Acl -LiteralPath $script:ConfigPath)
        $null = Assert-SshdConfigurationValid -ConfigPath $candidatePath

        $effectiveCandidate = Get-EffectiveSshdSettings -TargetUser $TargetUser -ConfigPath $candidatePath
        foreach ($requirement in @{
            pubkeyauthentication = 'yes'
            passwordauthentication = 'no'
            permitemptypasswords = 'no'
        }.GetEnumerator()) {
            if (-not $effectiveCandidate.ContainsKey($requirement.Key) -or
                $effectiveCandidate[$requirement.Key].ToLowerInvariant() -ne $requirement.Value) {
                throw "Candidate configuration does not make '$($requirement.Key) $($requirement.Value)' effective for $($TargetUser.AccountName)."
            }
        }

        if ($effectiveCandidate.ContainsKey('authenticationmethods')) {
            $authenticationMethods = $effectiveCandidate.authenticationmethods.ToLowerInvariant()
            $hasPublicKeyOnlyPath = $authenticationMethods -eq 'any' -or
                'publickey' -in @($authenticationMethods -split '\s+')
            if (-not $hasPublicKeyOnlyPath) {
                throw "Existing AuthenticationMethods '$authenticationMethods' does not provide a publickey-only login path for $($TargetUser.AccountName). The helper will not rewrite it."
            }
        }

        if ($AccessMode -eq 'Enable') {
            if (-not $effectiveCandidate.ContainsKey('allowusers') -or
                $effectiveCandidate.allowusers -notmatch "(?i)(^|\s)$([Regex]::Escape($TargetUser.SshdUserName))(\s|$)") {
                throw "Candidate configuration does not make the requested AllowUsers restriction effective."
            }
        }

        Copy-Item -LiteralPath $script:ConfigPath -Destination $script:ConfigBackupPath -Force
        [System.IO.File]::Move($candidatePath, $script:ConfigPath, $true)

        try {
            $null = Assert-SshdConfigurationValid -ConfigPath $script:ConfigPath
        }
        catch {
            Copy-Item -LiteralPath $script:ConfigBackupPath -Destination $script:ConfigPath -Force
            throw "The live sshd_config failed validation and was restored from $($script:ConfigBackupPath). $($_.Exception.Message)"
        }
    }
    finally {
        if (Test-Path -LiteralPath $candidatePath) {
            Remove-Item -LiteralPath $candidatePath -Force
        }
    }

    Write-Result CHANGE "Updated sshd_config. Previous configuration: $($script:ConfigBackupPath)"
    return $true
}

function Restart-SshdSafely {
    param([switch] $OnlyIfChanged, [bool] $Changed = $true)

    if ($OnlyIfChanged -and -not $Changed) {
        Write-Result OK 'sshd restart is unnecessary because its configuration did not change.'
        return $false
    }

    $null = Assert-SshdConfigurationValid
    $service = Get-Service -Name sshd -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        Restart-Service -Name sshd
        Write-Result CHANGE 'Restarted sshd after successful configuration validation.'
    }
    else {
        Start-Service -Name sshd
        Write-Result CHANGE 'Started sshd after successful configuration validation.'
    }

    $service = Get-Service -Name sshd
    if ($service.Status -ne 'Running') {
        throw "sshd did not reach the Running state. Current status: $($service.Status)"
    }
    return $true
}

function Assert-KeyInstalledForAuthenticationChange {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)] $KeyInfo
    )

    $context = Get-AuthorizedKeysContext -TargetUser $TargetUser
    if (-not (Test-PublicKeyInstalled -KeyInfo $KeyInfo -AuthorizedKeysPath $context.Path)) {
        throw "The supplied public key is not installed in the effective file '$($context.Path)'. Install it before disabling password authentication."
    }
    $aclStatus = Get-AuthorizedKeysAclStatus -TargetUser $TargetUser -Context $context
    if ($aclStatus -ne 'Correct') {
        throw "The effective authorized-keys ACL is not ready ($aclStatus). Normalize it before disabling password authentication: $($context.Path)"
    }
    return $context
}

function Set-AuthenticationPolicy {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)] $KeyInfo,
        [ValidateSet('Preserve', 'Enable', 'Disable')]
        [string] $AccessMode = 'Preserve'
    )

    $null = Assert-KeyInstalledForAuthenticationChange -TargetUser $TargetUser -KeyInfo $KeyInfo
    $changed = Set-SshdManagedConfiguration -TargetUser $TargetUser -AccessMode $AccessMode
    $null = Restart-SshdSafely -OnlyIfChanged -Changed $changed
    return $changed
}

function Show-SshBootstrapStatus {
    param(
        [Parameter(Mandatory)] $TargetUser,
        $KeyInfo
    )

    $capability = Get-OpenSshServerCapability
    $installed = $null -ne $capability -and $capability.State -eq 'Installed'
    $serviceInfo = if ($installed) { Get-SshdServiceInfo } else { $null }
    $firewallRule = if ($installed) {
        $standard = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $standard -and (Test-FirewallRuleAllowsSsh -Rule $standard)) { $standard }
        else { Get-EquivalentSshFirewallRule }
    }
    else { $null }

    $context = $null
    $settings = $null
    $validation = $null
    $aclStatus = 'Unavailable'
    $statusError = $null
    if ($installed -and (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        try {
            $validation = Test-SshdConfiguration
            if ($validation.Passed) {
                $context = Get-AuthorizedKeysContext -TargetUser $TargetUser
                $settings = $context.EffectiveSettings
                $aclStatus = Get-AuthorizedKeysAclStatus -TargetUser $TargetUser -Context $context
            }
        }
        catch {
            $statusError = $_.Exception.Message
        }
    }

    $keyStatus = if ($null -eq $KeyInfo) {
        'Not checked (no -PublicKeyFile)'
    }
    elseif ($null -ne $context -and (Test-PublicKeyInstalled -KeyInfo $KeyInfo -AuthorizedKeysPath $context.Path)) {
        'Installed'
    }
    else {
        'Not installed'
    }

    $validationStatus = if ($null -eq $validation) { 'Unavailable' }
        elseif ($validation.Passed) { 'Passed' }
        else { "Failed: $($validation.Output)" }
    $passwordLoginStatus = if ($null -eq $settings) { 'Unknown' }
        elseif ($settings.passwordauthentication -eq 'no') { 'Disabled' }
        else { "Enabled ($($settings.passwordauthentication))" }
    $publicKeyLoginStatus = if ($null -eq $settings) { 'Unknown' }
        elseif ($settings.pubkeyauthentication -eq 'yes') { 'Enabled' }
        else { "Disabled ($($settings.pubkeyauthentication))" }
    $emptyPasswordStatus = if ($null -eq $settings) { 'Unknown' }
        elseif ($settings.permitemptypasswords -eq 'no') { 'Disabled' }
        else { "Enabled ($($settings.permitemptypasswords))" }

    Write-Host ''
    Write-Host 'Windows OpenSSH helper status'
    Write-Host ''
    Write-Host ("User:                 {0}" -f $TargetUser.AccountName)
    Write-Host ("User SID:             {0}" -f $TargetUser.Sid.Value)
    Write-Host ("Direct admin member:  {0}" -f $TargetUser.DirectAdministrator)
    Write-Host ("OpenSSH Server:       {0}" -f $(if ($installed) { 'Installed' } else { 'Not installed' }))
    Write-Host ("sshd:                 {0}" -f $(if ($null -ne $serviceInfo) { "$($serviceInfo.State) / $($serviceInfo.StartMode)" } else { 'Unavailable' }))
    Write-Host 'SSH Port:             22'
    Write-Host ("Firewall:             {0}" -f $(if ($null -ne $firewallRule) { "Enabled ($($firewallRule.Name))" } else { 'Not ready' }))
    Write-Host ("Authorized keys:      {0}" -f $(if ($null -ne $context) { $context.Path } else { 'Unavailable' }))
    Write-Host ("Key-file ACL:         {0}" -f $aclStatus)
    Write-Host ("Administrator route:  {0}" -f $(if ($null -ne $context) { $context.UsesAdministratorFile } else { 'Unknown' }))
    Write-Host ("Public key:           {0}" -f $keyStatus)
    Write-Host ("Password login:       {0}" -f $passwordLoginStatus)
    Write-Host ("Public key login:     {0}" -f $publicKeyLoginStatus)
    Write-Host ("Empty passwords:      {0}" -f $emptyPasswordStatus)
    Write-Host ("AllowUsers:           {0}" -f $(if ($null -ne $settings -and $settings.ContainsKey('allowusers')) { $settings.allowusers } else { '(not set)' }))
    Write-Host ("Config validation:    {0}" -f $validationStatus)
    if ($statusError) {
        Write-Host ("Status diagnostic:    {0}" -f $statusError)
    }
    Write-Host ''
}

function Invoke-RecommendedSetup {
    param(
        [Parameter(Mandatory)] $TargetUser,
        [Parameter(Mandatory)] $KeyInfo
    )

    $null = Ensure-OpenSshServer
    $null = Install-PublicKey -TargetUser $TargetUser -KeyInfo $KeyInfo
    $configChanged = Set-SshdManagedConfiguration -TargetUser $TargetUser -AccessMode Preserve
    $null = Ensure-SshFirewallRule
    $null = Ensure-SshdService
    $null = Restart-SshdSafely -OnlyIfChanged -Changed $configChanged
    Show-SshBootstrapStatus -TargetUser $TargetUser -KeyInfo $KeyInfo
}

function Read-MenuUserName {
    param([string] $CurrentUserName)

    $value = Read-Host "Target Windows user [$CurrentUserName]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $CurrentUserName }
    return $value.Trim()
}

function Read-MenuPublicKeyFile {
    param([string] $CurrentPath)

    $prompt = if ($CurrentPath) { "Public-key file [$CurrentPath]" } else { 'Public-key file' }
    $value = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($value)) {
        if ($CurrentPath) { return $CurrentPath }
        throw 'A public-key file is required.'
    }
    return $value.Trim().Trim('"')
}

function Invoke-SelectedAction {
    param(
        [Parameter(Mandatory)][string] $SelectedAction,
        [Parameter(Mandatory)][string] $SelectedUserName,
        [string] $SelectedPublicKeyFile
    )

    $targetUser = $null
    $keyInfo = $null
    if ($SelectedAction -notin @('InstallServer', 'ConfigureService', 'ConfigureFirewall', 'ValidateConfiguration', 'RestartSshd')) {
        $targetUser = Resolve-TargetUser -Name $SelectedUserName
    }
    if ($SelectedAction -in @('InstallPublicKey', 'ConfigureAuthentication', 'RestrictToUser', 'RemoveUserRestriction', 'RecommendedSetup')) {
        $keyInfo = Get-PublicKeyInfo -Path $SelectedPublicKeyFile
    }
    elseif ($SelectedAction -eq 'Status' -and $SelectedPublicKeyFile) {
        $keyInfo = Get-PublicKeyInfo -Path $SelectedPublicKeyFile
    }

    switch ($SelectedAction) {
        'Status' {
            Show-SshBootstrapStatus -TargetUser $targetUser -KeyInfo $keyInfo
        }
        'InstallServer' {
            $null = Ensure-OpenSshServer
        }
        'ConfigureService' {
            $null = Ensure-SshdService
        }
        'ConfigureFirewall' {
            $null = Ensure-SshFirewallRule
        }
        'InstallPublicKey' {
            $null = Install-PublicKey -TargetUser $targetUser -KeyInfo $keyInfo
        }
        'NormalizeKeyAcl' {
            Assert-OpenSshServerInstalled
            $context = Get-AuthorizedKeysContext -TargetUser $targetUser
            $null = Ensure-AuthorizedKeysAcl -TargetUser $targetUser -Context $context
        }
        'ConfigureAuthentication' {
            $null = Set-AuthenticationPolicy -TargetUser $targetUser -KeyInfo $keyInfo -AccessMode Preserve
        }
        'RestrictToUser' {
            $null = Set-AuthenticationPolicy -TargetUser $targetUser -KeyInfo $keyInfo -AccessMode Enable
        }
        'RemoveUserRestriction' {
            $null = Set-AuthenticationPolicy -TargetUser $targetUser -KeyInfo $keyInfo -AccessMode Disable
        }
        'ValidateConfiguration' {
            Assert-OpenSshServerInstalled
            $null = Assert-SshdConfigurationValid
            Write-Result OK 'sshd_config validation passed.'
        }
        'RestartSshd' {
            Assert-OpenSshServerInstalled
            $null = Restart-SshdSafely
        }
        'RecommendedSetup' {
            Invoke-RecommendedSetup -TargetUser $targetUser -KeyInfo $keyInfo
        }
        default {
            throw "Unsupported action: $SelectedAction"
        }
    }
}

function Show-Menu {
    $menuUserName = $UserName
    $menuPublicKeyFile = $PublicKeyFile

    while ($true) {
        Write-Host ''
        Write-Host 'Windows OpenSSH Server Helper'
        Write-Host ''
        Write-Host ' 1. Show status'
        Write-Host ' 2. Install OpenSSH Server'
        Write-Host ' 3. Configure and start sshd service'
        Write-Host ' 4. Configure Windows Firewall for TCP 22'
        Write-Host ' 5. Install a public key'
        Write-Host ' 6. Normalize authorized_keys ACL'
        Write-Host ' 7. Enable public-key authentication and disable passwords'
        Write-Host ' 8. Restrict SSH login to one user (AllowUsers)'
        Write-Host ' 9. Remove the helper-managed AllowUsers restriction'
        Write-Host '10. Validate sshd_config'
        Write-Host '11. Safely restart sshd'
        Write-Host '12. Run the recommended setup sequence'
        Write-Host ' Q. Quit'
        Write-Host ''

        $choice = (Read-Host 'Select an option').Trim()
        if ($choice -match '^(?i:q|quit|exit)$') {
            return
        }

        $selectedAction = switch ($choice) {
            '1' { 'Status' }
            '2' { 'InstallServer' }
            '3' { 'ConfigureService' }
            '4' { 'ConfigureFirewall' }
            '5' { 'InstallPublicKey' }
            '6' { 'NormalizeKeyAcl' }
            '7' { 'ConfigureAuthentication' }
            '8' { 'RestrictToUser' }
            '9' { 'RemoveUserRestriction' }
            '10' { 'ValidateConfiguration' }
            '11' { 'RestartSshd' }
            '12' { 'RecommendedSetup' }
            default { $null }
        }
        if (-not $selectedAction) {
            Write-Result WARN 'Unknown menu selection.'
            continue
        }

        try {
            if ($selectedAction -notin @('InstallServer', 'ConfigureService', 'ConfigureFirewall', 'ValidateConfiguration', 'RestartSshd')) {
                $menuUserName = Read-MenuUserName -CurrentUserName $menuUserName
            }
            if ($selectedAction -in @('InstallPublicKey', 'ConfigureAuthentication', 'RestrictToUser', 'RemoveUserRestriction', 'RecommendedSetup')) {
                $menuPublicKeyFile = Read-MenuPublicKeyFile -CurrentPath $menuPublicKeyFile
            }
            Invoke-SelectedAction `
                -SelectedAction $selectedAction `
                -SelectedUserName $menuUserName `
                -SelectedPublicKeyFile $menuPublicKeyFile
        }
        catch {
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

try {
    Assert-Environment
    if ($Action -eq 'Menu') {
        Show-Menu
    }
    else {
        Invoke-SelectedAction `
            -SelectedAction $Action `
            -SelectedUserName $UserName `
            -SelectedPublicKeyFile $PublicKeyFile
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
