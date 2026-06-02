# entraId.ps1

`entraId.ps1` performs focused deep-dive enumeration for Microsoft Entra ID identities, roles, groups, applications, devices, Administrative Units, Azure Resource Manager visibility, Key Vault, Storage, and managed identities.

This script does not authenticate by itself. Prepare the required Microsoft Graph session, Az PowerShell context, or access token before running it.

## Requirements by Type

| Type | Requirement |
|---|---|
| `del`, `app`, `apps`, `group`, `role`, `au`, `owner`, `device` | Active Microsoft Graph PowerShell session. |
| `graph` | Valid `$Graph` token. `Connect-MgGraph` is optional for token inspection. |
| `arm`, `mi` | Active `Connect-AzAccount` session and `$ARM` token. |
| `keyvault` | `$KeyVault` token for `https://vault.azure.net`. |
| `storage` | `$AzureStorage` token for `https://storage.azure.com`. |

## Supported Types

| Type | Purpose |
|---|---|
| `del` | User/delegated identity deep dive: roles, groups, AUs, OAuth grants, app role assignments, owned objects, devices, auth methods, and licenses. |
| `app` | Service principal/application deep dive: roles, app permissions, OAuth grants, owners, owned objects, required resource access, key credentials, and password credentials. |
| `apps` | Application overview using a Graph token. |
| `group` | Group properties, owners, role assignments, app role assignments, transitive members, and dynamic membership rules. |
| `role` | Directory role definition, allowed actions, active assignments, and eligible PIM assignments. |
| `graph` | JWT token inspection. |
| `arm` | ARM context, subscriptions, resources, RBAC, effective permissions, Key Vaults, and Storage Accounts visible to the current identity. |
| `au` | Administrative Unit members. |
| `owner` | Objects owned by a service principal. |
| `device` | Device details and registered owners. |
| `keyvault` | Key Vault certificates, keys, and secrets. |
| `storage` | Storage containers and blobs. |
| `mi` | Managed identities visible from the current Azure context. |

## Basic Usage

```powershell
.\entraId.ps1 -Help
.\entraId.ps1
```

## Graph Token Inspection

Decodes token claims such as identity type, scopes, audience, client ID, app name, issue time, validity, and expiration.

```powershell
.\entraId.ps1 -Type graph -GraphToken $Graph
```

## User / Delegated Identity

Enumerates direct roles, roles via group, transitive groups, Administrative Units, AU-scoped roles, OAuth grants, app role assignments, owned objects, owned or registered devices, authentication methods, and licenses.

```powershell
# By display name
.\entraId.ps1 -Type del -Identity user_display_name -Tenant tenant.com

# By UPN
.\entraId.ps1 -Type del -Identity user@tenant.com -Tenant tenant.com

# By object ID
.\entraId.ps1 -Type del -Identity object_id -Tenant tenant.com

# Guest user in an external tenant; object ID is usually required
.\entraId.ps1 -Type del -Identity object_id -Tenant external_tenant.com
```

## Application / Service Principal

Enumerates direct roles, roles via group, transitive memberships, Administrative Units, Graph app roles, OAuth grants, owners, owned objects, required resource access, key credentials, and password credentials.

```powershell
.\entraId.ps1 -Type app -Identity app_name -Tenant tenant.com
.\entraId.ps1 -Type apps -GraphToken $Graph
```

## Device

When the hostname is unknown, first identify devices registered by a user:

```powershell
Get-MgUserRegisteredDevice -UserId "user@tenant.com" | Select-Object -ExpandProperty AdditionalProperties
```

Then enumerate the device:

```powershell
.\entraId.ps1 -Type device -Identity device_name_or_device_id
```

## Group

Enumerates role assignments, effective permissions, owners, app role assignments, transitive members, group type, dynamic membership rules, and role-assignable status.

```powershell
.\entraId.ps1 -Type group -Identity group_name -Tenant tenant.com
```

## Role

Enumerates a built-in or custom directory role, including allowed actions, active assignments, and eligible PIM assignments.

```powershell
.\entraId.ps1 -Type role -Identity "role_name" -Tenant tenant.com
```

## Administrative Unit

Accepts display name or GUID and enumerates AU members.

```powershell
.\entraId.ps1 -Type au -Identity au_name_or_guid
```

## Owner

Enumerates applications, groups, or other objects where a service principal is listed as owner. Accepts display name or object ID.

```powershell
.\entraId.ps1 -Type owner -Identity sp_name_or_object_id
```

## Azure Resource Manager

Enumerates resources, RBAC roles, effective permissions per resource, Key Vaults, and Storage Accounts visible from the current Azure context.

```powershell
.\entraId.ps1 -Type arm -ArmToken $ARM
```

ARM visibility is based on the current token identity. There is no ARM equivalent of Entra Global Reader; the script only sees what the authenticated user or service principal can see through Azure RBAC.

## Key Vault Data Plane

Lists certificates, keys, and secrets from a Key Vault.

```powershell
.\entraId.ps1 -Type keyvault -KeyVaultToken $KeyVault -VaultName "vault_name"
```

Required data-plane permissions include `keys/list`, `secrets/list`, and `certificates/list` on the target vault, depending on what you want to enumerate.

## Storage Data Plane

Lists containers and blobs from a Storage Account.

```powershell
.\entraId.ps1 -Type storage -StorageToken $AzureStorage -StorageName "storage_account_name"
```

Requires blob read permissions, such as `Storage Blob Data Reader`, on the target storage scope.
