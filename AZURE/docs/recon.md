# recon.ps1

`recon.ps1` maps Microsoft Entra ID tenant objects, builds local identity caches, searches those caches, exports application credential metadata, and reviews authentication methods, cross-tenant settings, and Conditional Access policy applicability.

## What It Does

- Enumerates users, groups, applications, service principals, directory roles, and Administrative Units.
- Writes CSV/TXT output into a local `identity_enum_<tenant>` folder.
- Searches local cache files by GUID, UPN, display name, or partial values.
- Optionally falls back to live Microsoft Graph search.
- Exports application registrations with `KeyCredentials` and `PasswordCredentials` metadata.
- Reviews authentication method policies.
- Reviews Cross-Tenant Access policy partners.
- Evaluates Conditional Access policies for users and service principals.

## Requirements

- Active Microsoft Graph PowerShell session.
- Read permissions appropriate to the selected workflow.
- Optional Az PowerShell context; the script continues if no Azure context exists.

## Useful Graph Permissions

| Workflow | Typical permissions |
|---|---|
| Tenant enumeration | `Directory.Read.All`, `Organization.Read.All`, `Group.Read.All`, `Application.Read.All` |
| Cache and live search | `Directory.Read.All`, `Group.Read.All`, `Application.Read.All` |
| Application correlation | `Application.Read.All` |
| Authentication methods and Conditional Access | `Policy.Read.All`, `Directory.Read.All`, `Group.Read.All`, `Application.Read.All` |

A Global Reader role normally covers the required read surface for many enumeration workflows.

## Main Modes and Switches

| Mode / Switch | Purpose |
|---|---|
| `-Mode enum` | Enumerates main tenant objects and generates local cache files. |
| `-Mode search` | Searches generated CSV cache files. |
| `-Live` | Uses live Microsoft Graph lookup if local cache search is insufficient. |
| `-Deep` | Enables broader Graph searches. Slower on large tenants. |
| `-Correlacion` | Exports complete application registration metadata, including key and password credentials. |
| `-AuthMeth` | Lists enabled authentication methods and Conditional Access summary. |
| `-AuthType <type>` | Shows detail for a specific authentication method. |
| `-Tenant` | Lists Cross-Tenant Access policy partners and trust settings. |
| `-CAP` | Evaluates Conditional Access policies for one identity. |
| `-Type user` | Evaluates a user identity for CAP scope. |
| `-Type sp` | Evaluates a service principal for workload identity CAP scope. |
| `-Detailed` | Shows additional policy fields. |
| `-Raw` | Shows raw Graph objects for debugging. |
| `-OutputPath` | Saves printed output to a text file. |

## Basic Usage

```powershell
.\recon.ps1 -Help
```

Enumerate the tenant and export application correlation data:

```powershell
.\recon.ps1 -Mode enum -Correlacion
```

Only export application correlation data:

```powershell
.\recon.ps1 -Correlacion
```

## Search Workflows

Run `-Mode enum` before local search. The search mode depends on the generated CSV cache.

```powershell
# Search by GUID
.\recon.ps1 -Mode search -Query "a3da1f7f-95f8-4eb1-9af9-138f36094d11"

# Search by UPN
.\recon.ps1 -Mode search -Query "user@tenant.com"

# Search by display name
.\recon.ps1 -Mode search -Query "app_name"

# Local cache plus live Graph lookup
.\recon.ps1 -Mode search -Query "SyncGroup" -Live

# Local cache plus broad live Graph search
.\recon.ps1 -Mode search -Query "student" -Live -Deep

# Use a custom cache directory
.\recon.ps1 -Mode search -Query "group_name" -CachePath "C:/lab/identity_enum_tenant_com"
```

## Authentication Method Review

```powershell
# Full policy summary: enabled CAPs and enabled authentication methods with targets
.\recon.ps1 -AuthMeth -OutputPath policies_recon.txt

# Method-specific detail
.\recon.ps1 -AuthType TAP
.\recon.ps1 -AuthType X509
.\recon.ps1 -AuthType FIDO2
.\recon.ps1 -AuthType MicrosoftAuthenticator
.\recon.ps1 -AuthType Email
.\recon.ps1 -AuthType SMS
```

| Auth Type | Focus |
|---|---|
| `TAP` | Temporary Access Pass lifetime, length, one-time use, targets, and group members. |
| `X509` | Certificate authentication mode, bindings, targets, and group members. |
| `FIDO2` | Security key attestation and key restriction settings. |
| `MicrosoftAuthenticator` | Number matching, software OATH, targets, and group members. |
| `Email` | Email OTP targets and group members. |
| `SMS` | SMS targets and group members. |

## Cross-Tenant Access

```powershell
# Cross-Tenant Access partners, MFA trust, and device compliance trust
.\recon.ps1 -Tenant

# Include B2B Collaboration and B2B Direct Connect detail
.\recon.ps1 -Tenant -Detailed
.
econ.ps1 -Help```

## Conditional Access by Identity

```powershell
# Evaluate CAPs that apply to a user
.\recon.ps1 -Identity "user@tenant.com" -CAP

# Add platforms, locations, session frequency, device filter, and risk levels
.\recon.ps1 -Identity "user@tenant.com" -CAP -Detailed

# Save output to a file
.\recon.ps1 -Identity "user@tenant.com" -CAP -Detailed -OutputPath ".\cap_user.txt"

# Evaluate workload identity policies for a service principal
.\recon.ps1 -Identity "AppName" -Type sp -CAP
.\recon.ps1 -Identity "AppName" -Type sp -CAP -Detailed

# Show the raw Microsoft Graph object
.\recon.ps1 -Identity "AppName" -Type sp -CAP -Raw
```

## Output Modes

| Mode | Fields shown | GUIDs resolved | Empty fields filtered | Recommended use |
|---|---|---:|---:|---|
| Normal | Basic fields | Yes | Yes | Fast review. |
| `-Detailed` | Basic plus extra fields | Yes | Yes | Daily recon workflow. |
| `-Raw` | Full raw Graph object | No | No | Debugging or field discovery. |

## Notes

- Run `-Mode enum` before `-Mode search`.
- Re-run `-Mode enum` if older CSVs contain embedded newlines or stale values.
- `-Correlacion` can run alone if an active Graph session or valid global `$Graph` token exists.
- Simple local cache search does not require additional live Graph permissions.
- Compatible with PowerShell 5.1 and PowerShell 7 when required Microsoft Graph modules are available.
