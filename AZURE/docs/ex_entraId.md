# ex_entraId.ps1

`ex_entraId.ps1` contains authorized action modules for Microsoft Entra ID and Azure assessment workflows. Some actions read sensitive data or modify tenant/resource state. Use only in environments where you have explicit authorization.

## Supported Actions

| Area | Type | Purpose |
|---|---|---|
| Key Vault | `kvjwt` | Generates a JWT client assertion signed by a private key stored in Key Vault. |
| Storage | `blobtag` | Replaces blob index tags for authorized ABAC testing. |
| Storage | `blobget` | Downloads a blob and reconstructs the file on disk. |
| ARM | `logicapp` | Retrieves and invokes Logic App callback URLs, extracts secondary trigger URLs, and optionally executes detected cases. |
| ARM | `joboutput` | Reads Azure Automation job output through ARM. |
| ARM | `runbookcontent` | Exports Azure Automation runbook source content. |
| Graph | `pimactivate` | Activates an eligible PIM role assignment. |
| Graph | `groupadd` | Adds a directory object to a group. |
| Graph | `changepass` | Resets a cloud-only user password. |
| Graph | `updateuser` | Updates a user attribute. |
| Graph | `graphread` | Reads OneDrive or mailbox content with an authorized Graph token. |

## Requirements by Area

| Area | Requirement |
|---|---|
| Key Vault | `$KeyVault` token with certificate read, key read, and `keys/sign/action`. |
| Storage | `$AzureStorage` token with the required blob data-plane permission. |
| ARM | `$ARM` token or active Az session with sufficient Azure RBAC. |
| Graph | Active Microsoft Graph session or `$Graph` token with required scopes/roles. |

## Key Vault: JWT Assertion Signing

`kvjwt` creates a `client_assertion` signed by a key stored in Azure Key Vault. The private key is not extracted. The script identifies a usable certificate, resolves the associated key, builds the JWT, and asks Key Vault to sign it through `keys/sign/action`.

| Permission / DataAction | Purpose |
|---|---|
| `Microsoft.KeyVault/vaults/certificates/read` | Read certificate metadata such as `id`, `kid`, `sid`, `x5t`, attributes, and policy. |
| `Microsoft.KeyVault/vaults/keys/read` | Read key metadata such as `kid`, `key_ops`, type, attributes, and enabled state. |
| `Microsoft.KeyVault/vaults/keys/sign/action` | Sign the JWT assertion with the Key Vault private key. |

```powershell
.\ex_entraId.ps1 -Type kvjwt -KeyVaultToken $KeyVault -VaultName "vault_name" -AppId "app_id" -TenantId "tenant_id"
```

Output variables:

| Variable | Description |
|---|---|
| `$JWTAssertionCandidates` | Certificates evaluated as possible JWT assertion signers. |
| `$AKVCertificate` | First valid certificate selected for signing. |
| `$signedJWT` | Signed JWT assertion ready for `get_token.ps1 -SignedJWT`. |

## Storage Actions

| Type | Required permission | Action |
|---|---|---|
| `blobtag` | `/storageAccounts/blobServices/containers/blobs/tags/write` | Replaces blob index tags to satisfy an authorized ABAC condition. |
| `blobget` | `/storageAccounts/blobServices/containers/blobs/read` | Downloads a blob and decodes Base64 content when applicable. |

```powershell
# Replace blob index tags
.\ex_entraId.ps1 -Type blobtag -StorageToken $AzureStorage -StorageName "storage_account_name" -ContainerName "container_name" -BlobName "blob_name" -TagKey "tag_key" -TagValue "tag_value"

# Download and reconstruct a blob
.\ex_entraId.ps1 -Type blobget -StorageToken $AzureStorage -StorageName "storage_account_name" -ContainerName "container_name" -BlobName "blob_name" -OutPath "C:/output/file.pfx"
```

`blobget` writes content as-is when the blob is not Base64. If the blob contains Base64 content, it decodes it and reconstructs the output file.

## ARM Actions

### Logic App

`logicapp` obtains the real callback URL, invokes it, extracts a secondary trigger URL, detects basic `display`, `execute`, and default cases, generates test URLs, and optionally executes them. It writes `callback_response.txt` and `logicapp_callback_summary.txt`.

```powershell
# Get callback URL and extract the second trigger URL
.\ex_entraId.ps1 -Type logicapp -LogicAppName "app_name" -ResourceGroupName "resource_group_name"

# Also execute display / execute / default cases
.\ex_entraId.ps1 -Type logicapp -LogicAppName "app_name" -ResourceGroupName "resource_group_name" -TriggerName "manual" -ExecuteCases
```

### Automation Account

```powershell
# Get job output
.\ex_entraId.ps1 -Type joboutput -ArmToken $ARM -SubscriptionId "subscription_id" -ResourceGroupName "resource_group_name" -AutomationAccountName "automation_account_name" -JobId "job_id"

# Export runbook source content
.\ex_entraId.ps1 -Type runbookcontent -SubscriptionId "subscription_id" -ResourceGroupName "resource_group_name" -AutomationAccountName "automation_account_name" -RunbookName "runbook_name" -OutputFolder "C:/output"
```

`runbookcontent` helps review what a runbook does and whether it handles credentials, connections, or calls to other services.

## Graph Actions

### PIM Activation

Activates an eligible PIM role assignment using `selfActivate`.

```powershell
.\ex_entraId.ps1 -Type pimactivate -Identity "user@tenant.com" -RoleName "role_name" -ScopeName "scope_name" -Duration "PT5M"
```

### Group Membership

```powershell
.\ex_entraId.ps1 -Type groupadd -GroupId "group_object_id" -MemberId "directory_object_id"
```

### User Updates

```powershell
# Reset a cloud-only user password
.\ex_entraId.ps1 -Type changepass -Identity "user@tenant.com" -Password "NewPass123!"

# Update a user attribute
.\ex_entraId.ps1 -Type updateuser -Identity "user@tenant.com" -Property "Department" -Value "value"
```

`changepass` fails when `OnPremisesSyncEnabled` is `True`, because the password source of authority is on-premises.

### Graph Read

Mail is usually more reliable in real environments. OneDrive is complementary and useful when the file still exists and the drive is provisioned.

```powershell
# List OneDrive files
.\ex_entraId.ps1 -Type graphread -Mode onedrive -GraphToken $Graph -Identity "user@tenant.com"

# Download a OneDrive file
.\ex_entraId.ps1 -Type graphread -Mode onedrive -GraphToken $Graph -Identity "user@tenant.com" -FileName "file_name" -OutputFolder "C:/output"

# List mailbox messages
.\ex_entraId.ps1 -Type graphread -Mode mail -GraphToken $Graph -Identity "user@tenant.com"

# Read a specific message
.\ex_entraId.ps1 -Type graphread -Mode mail -GraphToken $Graph -Identity "user@tenant.com" -MessageId "message_id"
```

| Vector | Advantage | Limitation |
|---|---|---|
| `mail` | Usually available when the user has a mailbox. | The useful message may already be deleted or moved. |
| `onedrive` | Direct file access when the object still exists. | Drive may not be provisioned, file may be deleted, or the user may not use OneDrive. |
