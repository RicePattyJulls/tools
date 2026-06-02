# Azure Entra ID Toolkit

PowerShell tooling and documentation for authorized Microsoft Entra ID and Azure security assessment workflows.

This folder is meant to be self-contained: scripts live in `scripts/`, and usage documentation lives in `docs/`.

## Intended Use

Use this toolkit only in tenants, subscriptions, labs, or client environments where you have explicit authorization. Some workflows require privileged Microsoft Graph scopes, Azure RBAC assignments, Key Vault data-plane permissions, or Storage data-plane permissions. Some actions can read sensitive data or change tenant/resource state.

## Contents

| Documentation | Script | Purpose |
|---|---|---|
| [`docs/get_token.md`](docs/get_token.md) | `get_token.ps1` | Obtain Graph, ARM, Key Vault, and Storage access tokens through delegated or app-only flows. |
| [`docs/recon.md`](docs/recon.md) | `recon.ps1` | Map tenant objects, search local identity cache, review authentication methods, cross-tenant access, and Conditional Access policy coverage. |
| [`docs/entraId.md`](docs/entraId.md) | `entraId.ps1` | Deep-dive enumeration for users, service principals, groups, roles, devices, Administrative Units, ARM, Key Vault, Storage, and managed identities. |
| [`docs/ex_entraId.md`](docs/ex_entraId.md) | `ex_entraId.ps1` | Authorized action modules for Key Vault, Storage, ARM, Automation Accounts, Logic Apps, PIM, groups, users, OneDrive, and mail. |

## Recommended Workflow

1. Use `get_token.ps1` to prepare the token or PowerShell session required for the target workflow.
2. Use `recon.ps1` for broad tenant and policy mapping.
3. Use `entraId.ps1` to inspect a specific identity, role, group, device, resource, Key Vault, or Storage Account.
4. Use `ex_entraId.ps1` only for explicitly authorized actions, especially when the action changes state or accesses sensitive data.

## Quick Start

From the repository root:

```powershell
Set-Location .\scripts

. .\get_token.ps1 -Help
.\recon.ps1 -Help
.\entraId.ps1 -Help
.\ex_entraId.ps1 -Help
```

Read the matching document before running each script:

```text
docs/get_token.md
docs/recon.md
docs/entraId.md
docs/ex_entraId.md
```

## Token and Session Model

The scripts are designed to work together:

- `get_token.ps1` stores tokens such as `$Graph`, `$ARM`, `$KeyVault`, and `$AzureStorage` when dot-sourced.
- `recon.ps1` and `entraId.ps1` rely on an active Microsoft Graph session, an active Az session, or prepared tokens depending on the selected mode.
- `ex_entraId.ps1` uses prepared tokens/sessions to perform authorized actions.
