# get_token.ps1

`get_token.ps1` obtains Microsoft Entra ID access tokens for Microsoft Graph, Azure Resource Manager, Azure Key Vault, and Azure Storage. Depending on the selected scope, it can also connect the matching PowerShell session with `Connect-MgGraph` or `Connect-AzAccount`.

## What It Does

- Requests access tokens for Graph, ARM, Key Vault, or Storage.
- Stores tokens in session variables when dot-sourced.
- Supports delegated and app-only authentication flows.
- Refreshes `$refresh_token` when the token endpoint returns a new one.
- Connects Microsoft Graph automatically for Graph tokens.
- Connects Az PowerShell automatically for ARM and Key Vault workflows.
- Leaves Storage as a raw token workflow for manual REST calls.

## Requirements

- PowerShell 5.1 or PowerShell 7.
- Microsoft Graph PowerShell module for Graph session connection.
- Az PowerShell module for ARM and Key Vault session connection.
- An authorized authentication input: refresh token, password, client secret, certificate, signed JWT assertion, or Device Code Flow.

## Important Usage Note

Dot-source the script if you want output variables to remain available in your current session:

```powershell
. .\get_token.ps1 -Scope graph -DeviceCode -TenantId "<TENANT_ID>" -ClientId "<CLIENT_ID>"
```

If you run it without dot-sourcing, the script can still execute, but variables such as `$Graph`, `$ARM`, `$KeyVault`, `$AzureStorage`, and `$refresh_token` will not persist in your shell.

## Output Variables

| Variable | Audience | Description |
|---|---|---|
| `$Graph` | `https://graph.microsoft.com` | Microsoft Graph access token. |
| `$ARM` | `https://management.azure.com` | Azure Resource Manager access token. |
| `$KeyVault` | `https://vault.azure.net` | Azure Key Vault data-plane access token. |
| `$AzureStorage` | `https://storage.azure.com` | Azure Storage data-plane access token. |
| `$refresh_token` | OAuth refresh token | Delegated refresh token when returned by the endpoint. |

## Supported Scopes

| Scope | Behavior |
|---|---|
| `graph` | Gets a Graph token and connects with `Connect-MgGraph`. |
| `arm` | Gets an ARM token, clears existing Az context, and connects with `Connect-AzAccount`. |
| `keyvault` | Gets a Key Vault token and connects Az PowerShell using ARM plus Key Vault tokens. |
| `storage` | Gets a Storage token and stores it in `$AzureStorage`; no Az context is created. |

## Supported Authentication Flows

| Flow | Parameters | Notes |
|---|---|---|
| Refresh Token | `-RefreshToken`, `-ClientId`, `-Identity`, `-TenantId` | Delegated token exchange. Useful when an authorized refresh token already exists. |
| Device Code | `-DeviceCode`, `-ClientId`, optional `-TenantId` | Interactive delegated authentication. Requests `offline_access`. |
| Password / ROPC | `-Password`, `-Identity`, `-ClientId`, `-TenantId` | Does not support MFA. Use mainly for labs or legacy service accounts. |
| Client Secret | `-ClientSecret`, `-Identity`, `-ClientId`, `-TenantId` | App-only client credentials flow. |
| Certificate | `-CertPath`, `-Identity`, `-ClientId`, `-TenantId` | App-only assertion signed with a local `.pfx`. |
| Signed JWT | `-SignedJWT`, `-Identity`, `-ClientId`, `-TenantId` | App-only assertion signed externally, for example through Key Vault. |

## Delegated Examples

Refresh token exchange:

```powershell
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope graph    -RefreshToken $refresh_token -ClientId "<CLIENT_ID>"
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope arm      -RefreshToken $refresh_token -ClientId "<CLIENT_ID>"
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope keyvault -RefreshToken $refresh_token -ClientId "<CLIENT_ID>"
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope storage  -RefreshToken $refresh_token -ClientId "<CLIENT_ID>"
```

Key Vault workflow, where both ARM and Key Vault tokens are required:

```powershell
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope arm      -RefreshToken $refresh_token -ClientId "<CLIENT_ID>"
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope keyvault -RefreshToken $refresh_token -ClientId "<CLIENT_ID>"
```

ROPC examples:

```powershell
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope graph -Password "<PASSWORD>" -ClientId "<CLIENT_ID>"
. .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<TENANT_ID>" -Scope arm   -Password "<PASSWORD>" -ClientId "<CLIENT_ID>"
```

Device Code Flow:

```powershell
# Tenant resolved during login
. .\get_token.ps1 -Scope graph -DeviceCode -ClientId "<CLIENT_ID>"

# Specific tenant
. .\get_token.ps1 -Scope graph -DeviceCode -TenantId "<TENANT_ID>" -ClientId "<CLIENT_ID>"
. .\get_token.ps1 -Scope arm   -DeviceCode -TenantId "<TENANT_ID>" -ClientId "<CLIENT_ID>"
```

## App-Only Examples

Client secret:

```powershell
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope graph -ClientSecret "<CLIENT_SECRET>" -ClientId "<APP_ID>"
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope arm   -ClientSecret "<CLIENT_SECRET>" -ClientId "<APP_ID>"
```

Certificate `.pfx`:

```powershell
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope graph -CertPath "C:/path/cert.pfx" -ClientId "<APP_ID>"
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope arm   -CertPath "C:/path/cert.pfx" -ClientId "<APP_ID>"
```

Signed JWT assertion:

```powershell
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope graph    -SignedJWT $signedJWT -ClientId "<APP_ID>"
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope arm      -SignedJWT $signedJWT -ClientId "<APP_ID>"
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope keyvault -SignedJWT $signedJWT -ClientId "<APP_ID>"
. .\get_token.ps1 -Identity "<APP_ID>" -TenantId "<TENANT_ID>" -Scope storage  -SignedJWT $signedJWT -ClientId "<APP_ID>"
```

A signed JWT can be generated with `ex_entraId.ps1 -Type kvjwt` when Key Vault signing is in scope.

## Storage REST Usage

The Storage scope does not create an Az context. Use `$AzureStorage` directly in REST calls:

```powershell
$URL = "https://<storage_account>.blob.core.windows.net/?comp=list"
Invoke-RestMethod -Method GET -Uri $URL -Headers @{
    Authorization  = "Bearer $AzureStorage"
    "x-ms-version" = "2020-04-08"
}
```
