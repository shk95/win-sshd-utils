#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [Parameter(Mandatory)][bool] $Condition,
        [Parameter(Mandatory)][string] $Message
    )

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'setup-openssh.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref] $tokens,
    [ref] $parseErrors
)
Assert-True ($parseErrors.Count -eq 0) 'setup-openssh.ps1 must parse without errors'

$functionNames = @(
    'Get-KeyIdentityFromAuthorizedKeyLine',
    'Get-ManagedConfigurationText',
    'Resolve-AuthorizedKeysPath',
    'New-DesiredFileAcl',
    'New-DesiredDirectoryAcl'
)
foreach ($functionName in $functionNames) {
    $functionAst = $ast.Find(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $functionName
        },
        $true
    )
    Assert-True ($null -ne $functionAst) "function $functionName must exist"
    Invoke-Expression $functionAst.Extent.Text
}

$script:ManagedBlockBegin = '# BEGIN managed by setup-openssh.ps1'
$script:ManagedBlockEnd = '# END managed by setup-openssh.ps1'
$script:AccessBackupPrefix = '# [setup-openssh.ps1 access-backup] '
$script:SupersededPrefix = '# [setup-openssh.ps1 superseded] '
$script:AdministratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$script:SystemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')

$blob = 'AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyPayloadForIdentityMatching'
$plainIdentity = Get-KeyIdentityFromAuthorizedKeyLine -Line "ssh-ed25519 $blob laptop"
$optionIdentity = Get-KeyIdentityFromAuthorizedKeyLine -Line "restrict,command=`"whoami`" ssh-ed25519 $blob renamed"
Assert-True ($plainIdentity -eq "ssh-ed25519 $blob") 'plain public key identity should ignore its comment'
Assert-True ($optionIdentity -eq $plainIdentity) 'authorized_keys options and comments should not affect identity'

$targetUser = [pscustomobject]@{
    AccountName = 'TESTPC\alice'
    SshdUserName = 'alice'
    ProfilePath = 'C:\Users\alice'
}
$administratorKeyPath = Resolve-AuthorizedKeysPath `
    -TargetUser $targetUser `
    -ConfiguredPath '__PROGRAMDATA__/ssh/administrators_authorized_keys'
$ordinaryKeyPath = Resolve-AuthorizedKeysPath `
    -TargetUser $targetUser `
    -ConfiguredPath '.ssh/authorized_keys'
Assert-True ($administratorKeyPath -eq "$env:ProgramData\ssh\administrators_authorized_keys") 'ProgramData token should resolve to the Windows administrator key path'
Assert-True ($ordinaryKeyPath -eq 'C:\Users\alice\.ssh\authorized_keys') 'relative key path should resolve below the target profile'

$administratorFileAcl = New-DesiredFileAcl `
    -OwnerSid $script:AdministratorsSid `
    -AllowedSids @($script:SystemSid, $script:AdministratorsSid)
$administratorSddl = $administratorFileAcl.GetSecurityDescriptorSddlForm(
    [System.Security.AccessControl.AccessControlSections]'Owner, Group, Access'
)
Assert-True ($administratorSddl -match ';;;SY\)') 'administrator key ACL should contain SYSTEM'
Assert-True ($administratorSddl -match ';;;BA\)') 'administrator key ACL should contain BUILTIN Administrators'

$initialConfig = @'
# Windows OpenSSH sample
PasswordAuthentication yes
PubkeyAuthentication no
PermitEmptyPasswords yes
AllowUsers alice bob

Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
'@

$managed = Get-ManagedConfigurationText -CurrentText $initialConfig
Assert-True ([regex]::Matches($managed, '(?m)^# BEGIN managed by setup-openssh\.ps1\r?$').Count -eq 1) 'managed block should occur once'
Assert-True ([regex]::Matches($managed, '(?m)^PasswordAuthentication no\r?$').Count -eq 1) 'password policy should have one active global line'
Assert-True ($managed.Contains('# [setup-openssh.ps1 superseded] PasswordAuthentication yes')) 'old authentication lines should be preserved as comments'

$managedAgain = Get-ManagedConfigurationText -CurrentText $managed
Assert-True ($managedAgain -ceq $managed) 'authentication configuration should be byte-idempotent after the first run'

$restricted = Get-ManagedConfigurationText -CurrentText $managed -AccessMode Enable -RestrictedUser 'Alice'
Assert-True ($restricted -match '(?m)^AllowUsers alice\r?$') 'managed AllowUsers should be normalized to lowercase'
Assert-True ($restricted.Contains('# [setup-openssh.ps1 access-backup] AllowUsers alice bob')) 'prior global AllowUsers should be preserved for recovery'

$restrictedAgain = Get-ManagedConfigurationText -CurrentText $restricted -AccessMode Enable -RestrictedUser 'Alice'
Assert-True ($restrictedAgain -ceq $restricted) 'user restriction should be byte-idempotent'

$unrestricted = Get-ManagedConfigurationText -CurrentText $restricted -AccessMode Disable
Assert-True ($unrestricted -match '(?m)^AllowUsers alice bob\r?$') 'removing the managed restriction should restore the prior AllowUsers line'
Assert-True ($unrestricted -notmatch '(?m)^AllowUsers alice\r?$') 'managed single-user AllowUsers should be removed'

$conflictingMatch = @'
# sample
Match User alice
    PasswordAuthentication yes
'@
$conflictDetected = $false
try {
    $null = Get-ManagedConfigurationText -CurrentText $conflictingMatch
}
catch {
    $conflictDetected = $_.Exception.Message -like "*inside a Match section*"
}
Assert-True $conflictDetected 'conflicting Match authentication policy should be rejected'

Write-Host 'Pure logic tests: passed'
