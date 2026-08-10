# Windows OpenSSH Server Helper

`setup-openssh.ps1` is an idempotent PowerShell 7 helper for inspecting and configuring the built-in Windows OpenSSH Server. It opens a menu by default, so installation, service, firewall, public-key, ACL, and authentication-policy work can be performed separately.

It is intended for personal and development Windows machines. It is not a general Windows hardening framework.

## Prerequisites

- Windows 11 or a recent Windows Server release
- PowerShell 7 (`pwsh`)
- An elevated **Run as administrator** terminal
- A valid SSH public-key file for key-related actions
- Access to Windows Update or another configured capability source when OpenSSH Server must be installed

Microsoft Entra accounts are not supported by Windows OpenSSH public-key authentication. Local Windows accounts and resolvable domain accounts with a local profile are supported where the installed Windows OpenSSH configuration supports them.

## Interactive use

Start the helper without an action:

```powershell
pwsh -File ./setup-openssh.ps1
```

The menu provides these operations:

1. Show status
2. Install OpenSSH Server
3. Configure and start the `sshd` service
4. Configure Windows Firewall for inbound TCP 22
5. Install a public key
6. Normalize the effective `authorized_keys` ACL
7. Enable public-key authentication and disable passwords
8. Restrict SSH login to one user with `AllowUsers`
9. Remove the helper-managed `AllowUsers` restriction
10. Validate `sshd_config`
11. Safely restart `sshd`
12. Run the recommended setup sequence

The selected target user and public-key path are remembered for the duration of the menu session.

## Direct actions

The same operations can be called noninteractively with `-Action`:

```powershell
# Inspect state without checking a particular key.
pwsh -File ./setup-openssh.ps1 -Action Status -UserName sh

# Install the Windows capability only.
pwsh -File ./setup-openssh.ps1 -Action InstallServer

# Install one key without duplicating an existing copy.
pwsh -File ./setup-openssh.ps1 `
    -Action InstallPublicKey `
    -UserName sh `
    -PublicKeyFile "$HOME/.ssh/id_ed25519.pub"

# Install the key first, then explicitly disable password authentication.
pwsh -File ./setup-openssh.ps1 `
    -Action ConfigureAuthentication `
    -UserName sh `
    -PublicKeyFile "$HOME/.ssh/id_ed25519.pub"
```

Available action names are:

```text
Status
InstallServer
ConfigureService
ConfigureFirewall
InstallPublicKey
NormalizeKeyAcl
ConfigureAuthentication
RestrictToUser
RemoveUserRestriction
ValidateConfiguration
RestartSshd
RecommendedSetup
```

`ConfigureAuthentication`, `RestrictToUser`, and `RemoveUserRestriction` require the supplied public key to already be present in the effective authorized-keys file and require its ACL to be normalized. This prevents the helper from disabling password authentication before verifying the server-side key installation.

For a full initial setup:

```powershell
pwsh -File ./setup-openssh.ps1 `
    -Action RecommendedSetup `
    -UserName sh `
    -PublicKeyFile "$HOME/.ssh/id_ed25519.pub"
```

The recommended sequence installs the capability, installs and protects the key, applies the authentication policy, configures the firewall and service, validates the configuration, and prints final status. Each underlying operation remains individually selectable.

## What the helper changes

- Installs the built-in `OpenSSH.Server` Windows capability when requested
- Sets `sshd` startup to Automatic and starts it when requested
- Reuses or creates an enabled inbound TCP 22 firewall rule
- Adds one public key without replacing unrelated keys
- Resolves the effective `AuthorizedKeysFile` with `sshd -T -C`
- Applies SID-based Windows ACLs to the key file
- Manages only this global authentication block in `%ProgramData%\ssh\sshd_config`:

```text
# BEGIN managed by setup-openssh.ps1
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
# END managed by setup-openssh.ps1
```

When requested, the block also contains `AllowUsers <username>`. Existing global `AllowUsers` lines are retained as marked comments and restored when the helper-managed restriction is removed.

Existing active global copies of the three authentication directives are retained as marked comments. Unrelated settings and comments are preserved. The managed block is placed before the first `Match` section because OpenSSH configuration ordering affects the resulting policy.

If a `Match` section contains a conflicting authentication setting, the helper stops instead of rewriting that conditional policy.

## Administrator accounts

The default Windows OpenSSH configuration sends administrator accounts to:

```text
C:\ProgramData\ssh\administrators_authorized_keys
```

This is a shared file for administrator accounts, not a per-user file. A key stored there is therefore not intrinsically tied to only the username supplied to this helper. Use the explicit `RestrictToUser` action if SSH access must be limited to one Windows account, and review any existing access rules before doing so.

The initial `RestrictToUser` implementation accepts ordinary account names without whitespace or SSH pattern metacharacters. Key installation and ACL management do not have this restriction.

The helper restricts this file to the following well-known SIDs:

- `S-1-5-18` — SYSTEM
- `S-1-5-32-544` — BUILTIN\Administrators

For an ordinary user's default `.ssh` directory and `authorized_keys`, the target user, SYSTEM, and BUILTIN\Administrators receive full control and inheritance is disabled. A custom authorized-keys directory is not rewritten; only the selected key file is protected.

## Validation and recovery

Before changing `sshd_config`, the helper writes a candidate beside the live file and validates it with the installed `sshd.exe -t -f`. It also checks the effective target-user policy with `sshd.exe -T -C`.

The last configuration replaced by this helper is stored at:

```text
C:\ProgramData\ssh\sshd_config.setup-openssh.last-good.bak
```

Only one last-good backup is kept. If live validation fails immediately after replacement, the helper restores it automatically. To restore it manually from an elevated PowerShell session:

```powershell
Copy-Item `
    "$env:ProgramData\ssh\sshd_config.setup-openssh.last-good.bak" `
    "$env:ProgramData\ssh\sshd_config" `
    -Force

& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
Restart-Service sshd
```

Never restart `sshd` after a failed validation. Review diagnostics in **Event Viewer → Applications and Services Logs → OpenSSH** when the service does not start.

`sshd -t` verifies configuration syntax and host keys. It does not prove an end-to-end login with the matching private key. Keep the elevated local session open and test a second SSH connection before relying exclusively on remote access.

## Intentionally not managed

The helper does not install or configure Tailscale, WireGuard, VPN-only access, IP allowlists, alternate SSH ports, user accounts, passwords, SSH agents, WSL SSH, custom ciphers/KEX/MAC policy, certificates, host-key rotation, or third-party Win32-OpenSSH builds.

## Logic tests

The repository includes dependency-free tests for key identity parsing, Windows key-path resolution, managed configuration idempotency, `AllowUsers` recovery, and conflicting `Match` detection:

```powershell
pwsh -File ./tests/test-pure-logic.ps1
```
