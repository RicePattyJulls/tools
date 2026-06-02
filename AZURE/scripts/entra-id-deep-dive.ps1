[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("del", "app", "apps", "group", "role", "arm", "graph", "au", "owner", "keyvault", "storage", "device", "mi")]
    [string]$Type,

    [Parameter()] [string]$Identity,
    [Parameter()] [string]$Tenant,
    [Parameter()] [string]$ArmToken,
    [Parameter()] [string]$GraphToken,
    [Parameter()] [string]$KeyVaultToken,
    [Parameter()] [string]$VaultName,
    [Parameter()] [string]$StorageToken,
    [Parameter()] [string]$StorageName,
    [Parameter()] [switch]$Help
)

if ($Type -in @("del","app","group","role","au","owner") -and -not $Identity) {
    throw "[-] -Identity es obligatorio para -Type '$Type'"
}
if ($Type -eq "device" -and -not $Identity) { throw "[-] -Identity es obligatorio para -Type 'device'." }
if ($Type -eq "arm" -and -not $ArmToken) { throw "[-] -ArmToken es obligatorio para -Type 'arm'." }
if ($Type -eq "keyvault" -and -not $KeyVaultToken) { throw "[-] -KeyVaultToken es obligatorio para -Type 'keyvault'." }
if ($Type -eq "keyvault" -and -not $VaultName) { throw "[-] -VaultName es obligatorio para -Type 'keyvault'." }
if ($Type -eq "storage" -and -not $StorageToken) { throw "[-] -StorageToken es obligatorio para -Type 'storage'." }
if ($Type -eq "storage" -and -not $StorageName) { throw "[-] -StorageName es obligatorio para -Type 'storage'." }

function Show-Help {
    Write-Host @"

entraId.ps1 -- Deep dive enumeration for Microsoft Entra ID and Azure ARM.

USAGE:
  .\entraId.ps1 -Type <type> [options]

TYPES:
  del       Enumerate user (delegated context)
  app       Enumerate Service Principal / Application
  apps      List all applications with notes field
  group     Enumerate security or M365 group
  role      Enumerate directory role (built-in or custom)
  graph     Inspect Graph JWT token claims
  arm       Enumerate Azure Resource Manager resources and RBAC
  au        Enumerate Administrative Unit members
  owner     Enumerate objects owned by a Service Principal
  keyvault  Enumerate certificates, keys and secrets from a Key Vault
  storage   Enumerate containers and blobs from a Storage Account
  device    Enumerate Entra ID device
  mi        Enumerate Managed Identities visible from current Az context (ARM-only)

"@ -ForegroundColor Cyan
}

function Test-IsGuid {
    param([string]$Value)
    $guid = [Guid]::Empty
    return [Guid]::TryParse($Value, [ref]$guid)
}

$script:RoleCache = @{}

function Resolve-Role {
    param($RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return $null }
    if ($script:RoleCache.ContainsKey($RoleDefinitionId)) { return $script:RoleCache[$RoleDefinitionId] }
    try {
        $raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$RoleDefinitionId" -ErrorAction Stop
        $def = [PSCustomObject]@{ DisplayName = $raw.displayName; RolePermissions = $raw.rolePermissions }
    } catch {
        $def = [PSCustomObject]@{ DisplayName = "(unresolvable: $RoleDefinitionId)"; RolePermissions = @() }
    }
    $script:RoleCache[$RoleDefinitionId] = $def
    return $def
}

function Get-RoleAssignments {
    param([string]$PrincipalId)
    try {
        $raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$PrincipalId'" -ErrorAction Stop
        return @($raw.value | ForEach-Object { [PSCustomObject]@{ RoleDefinitionId=$_.roleDefinitionId; DirectoryScopeId=$_.directoryScopeId; PrincipalId=$_.principalId } })
    } catch { return @() }
}

function Resolve-Principal {
    param($PrincipalId)
    try {
        $obj = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId" -ErrorAction Stop
        switch ($obj.'@odata.type') {
            '#microsoft.graph.user'             { return "User" }
            '#microsoft.graph.group'            { return "Group" }
            '#microsoft.graph.servicePrincipal' { return "ServicePrincipal" }
            default                             { return "Unknown" }
        }
    } catch { return "Unknown" }
}

function Resolve-ResourceSP { param($ResourceId); try { Get-MgServicePrincipal -ServicePrincipalId $ResourceId } catch { $null } }

function Get-AUMembershipType {
    param([string]$AUId)
    try {
        $au = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/${AUId}?`$select=id,displayName,membershipType" -ErrorAction Stop
        $mt = $au.membershipType
        if ([string]::IsNullOrWhiteSpace($mt)) { return "membership" }
        return $mt
    } catch { return "(unknown)" }
}

function Format-Roles {
    param($Assignments)
    $valid = @($Assignments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.RoleDefinitionId) })
    if ($valid.Count -eq 0) { return "(none)" }
    ($valid | ForEach-Object { $role = Resolve-Role $_.RoleDefinitionId; "RoleName        : $($role.DisplayName)`nRoleDefinitionId: $($_.RoleDefinitionId)`nScope           : $($_.DirectoryScopeId)`n" }) -join "`n"
}

function Format-Groups {
    param($Groups)
    $valid = @($Groups | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Id) })
    if ($valid.Count -eq 0) { return "(none)" }
    ($valid | ForEach-Object { "DisplayName : $($_.AdditionalProperties.displayName)`nId          : $($_.Id)" }) -join "`n"
}

function Format-AUs {
    param($AUs)
    $valid = @($AUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Id) })
    if ($valid.Count -eq 0) { return "(none)" }
    ($valid | ForEach-Object { $mt = Get-AUMembershipType -AUId $_.Id; "DisplayName    : $($_.AdditionalProperties.displayName)`nId             : $($_.Id)`nMembershipType : $mt`n" }) -join "`n"
}

function Format-OwnedObjects {
    param($Objects)
    $valid = @($Objects | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Id) })
    if ($valid.Count -eq 0) { return "(none)" }
    ($valid | ForEach-Object { "Id          : $($_.Id)`nDisplayName : $($_.AdditionalProperties.displayName)`nObjectType  : $($_.AdditionalProperties.'@odata.type')`n" }) -join "`n"
}

function Get-JwtPayload {
    param([string]$Token)
    $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

function Show-TokenContext {
    param([string]$TokenName, [string]$Token)
    try { $claims = Get-JwtPayload -Token $Token } catch { Write-Warning "[$TokenName] No se pudo decodificar el token."; return }
    $identityType   = if ($claims.roles) { "AppOnly / Service Principal" } elseif ($claims.scp) { "Delegated / User" } else { "Unknown" }
    $userIdentity   = if ($claims.upn) { $claims.upn } elseif ($claims.preferred_username) { $claims.preferred_username } elseif ($claims.name) { $claims.name } else { $claims.oid }
    $clientIdentity = if ($claims.appid) { $claims.appid } elseif ($claims.azp) { $claims.azp } else { "(unknown)" }
    $expUtc = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).UtcDateTime } else { $null }
    $iatUtc = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).UtcDateTime } else { $null }
    $nbfUtc = if ($claims.nbf) { [DateTimeOffset]::FromUnixTimeSeconds($claims.nbf).UtcDateTime } else { $null }
    $expired = if ($expUtc) { [DateTime]::UtcNow -gt $expUtc } else { $null }
    Write-Host "`n------------------------------------------" -ForegroundColor Cyan
    Write-Host " TOKEN CONTEXT - $($TokenName.ToUpper())" -ForegroundColor Cyan
    Write-Host "------------------------------------------" -ForegroundColor Cyan
    [PSCustomObject]@{ Token=$TokenName.ToUpper(); IdentityType=$identityType; UserIdentity=$userIdentity; UserDisplayName=$claims.name; UserPrincipalName=$claims.upn; UserObjectId=$claims.oid; ClientId=$clientIdentity; ClientAppName=$claims.app_displayname; TenantId=$claims.tid; Audience=$claims.aud; Roles=($claims.roles -join ", "); Scopes=$claims.scp; IssuedAt=$iatUtc; NotBefore=$nbfUtc; ExpiresAt=$expUtc; IsExpired=$expired } | Format-List
}

$TargetIdentity = if (Test-IsGuid -Value $Identity) { $Identity } elseif ($Identity -notmatch "@") { "$Identity@$Tenant" } else { $Identity }

if ($Help -or -not $Type) { Show-Help; exit 0 }

# =============================================================
# DEL
# =============================================================
if ($Type -eq "del") {
    $org  = Get-MgOrganization
    $user = Get-MgUser -UserId $TargetIdentity
    $transitiveMemberOf  = Get-MgUserTransitiveMemberOf -UserId $user.Id -All
    $groups              = @($transitiveMemberOf | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' })
    $administrativeUnits = @($transitiveMemberOf | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.administrativeUnit' })
    $directAssignments   = Get-RoleAssignments -PrincipalId $user.Id
    $groupAssignments    = @(foreach ($g in $groups) { Get-RoleAssignments -PrincipalId $g.Id })
    $auScopedAssignments = @(foreach ($au in $administrativeUnits) {
        try { $raw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=directoryScopeId eq '/administrativeUnits/$($au.Id)'" -ErrorAction Stop; $raw.value | ForEach-Object { [PSCustomObject]@{ RoleDefinitionId=$_.roleDefinitionId; DirectoryScopeId=$_.directoryScopeId; PrincipalId=$_.principalId } } } catch {}
    })
    try   { $oauthGrants = @(Get-MgOauth2PermissionGrant -Filter "principalId eq '$($user.Id)'" -ErrorAction Stop) } catch { $oauthGrants = @() }
    $appRoleAssignments = @(Get-MgUserAppRoleAssignment -UserId $user.Id)
    $ownedObjects       = @(Get-MgUserOwnedObject -UserId $user.Id)
    $ownedDevices       = @(Get-MgUserOwnedDevice -UserId $user.Id)
    $registeredDevices  = @(Get-MgUserRegisteredDevice -UserId $user.Id)
    try   { $authMethods    = @(Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop) } catch { $authMethods = @() }
    try   { $licenseDetails = @(Get-MgUserLicenseDetail -UserId $user.Id) } catch { $licenseDetails = @() }

    $auScopedStr = if ($auScopedAssignments.Count -eq 0) { "(none)" } else {
        $validAU = @($auScopedAssignments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.RoleDefinitionId) })
        if ($validAU.Count -eq 0) { "(none)" } else { ($validAU | ForEach-Object { $role = Resolve-Role $_.RoleDefinitionId; $pt = Resolve-Principal $_.PrincipalId; "RoleName        : $($role.DisplayName)`nRoleDefinitionId: $($_.RoleDefinitionId)`nPrincipalId     : $($_.PrincipalId)`nPrincipalType   : $pt`nScope           : $($_.DirectoryScopeId)`n" }) -join "`n" }
    }

    $eligibleRolesStr = "(none)"
    try {
        $eligibleInstances = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "principalId eq '$($user.Id)'" -ExpandProperty "roleDefinition,directoryScope" -All -ErrorAction Stop)
        if ($eligibleInstances.Count -gt 0) {
            $eligibleRolesStr = ($eligibleInstances | ForEach-Object {
                $roleName  = if ($_.RoleDefinition) { $_.RoleDefinition.DisplayName } else { $_.RoleDefinitionId }
                $scopeName = if ($_.DirectoryScope -and $_.DirectoryScope.AdditionalProperties.displayName) { $_.DirectoryScope.AdditionalProperties.displayName } else { $_.DirectoryScopeId }
                "RoleName        : $roleName`nRoleDefinitionId: $($_.RoleDefinitionId)`nScope           : $($_.DirectoryScopeId)`nScopeName       : $scopeName`nMemberType      : $($_.MemberType)`nStart           : $($_.StartDateTime)`nEnd             : $(if ($_.EndDateTime) { $_.EndDateTime } else { 'Permanent' })`n"
            }) -join "`n"
        }
    } catch { $eligibleRolesStr = "(error querying eligible roles)" }

    $oauthStr   = if ($oauthGrants.Count -eq 0) { "(none)" } else { ($oauthGrants | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ClientId) } | ForEach-Object { "ClientId    : $($_.ClientId)`nConsentType : $($_.ConsentType)`nScope       : $($_.Scope)`nResourceId  : $($_.ResourceId)`n" }) -join "`n" }
    $appRoleStr = if ($appRoleAssignments.Count -eq 0) { "(none)" } else { ($appRoleAssignments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ResourceId) } | ForEach-Object { $rsp = Get-MgServicePrincipal -ServicePrincipalId $_.ResourceId; "Resource     : $($rsp.DisplayName)`nSPType       : $($rsp.ServicePrincipalType)`nResourceId   : $($_.ResourceId)`nAppRoleId    : $($_.AppRoleId)`n" }) -join "`n" }
    $authStr    = if ($authMethods.Count -eq 0) { "(none)" } else { ($authMethods | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Id) } | ForEach-Object { "MethodId    : $($_.Id)`nMethodType  : $($_.AdditionalProperties.'@odata.type')`n" }) -join "`n" }
    $licStr     = if ($licenseDetails.Count -eq 0) { "(none)" } else { ($licenseDetails | ForEach-Object { "SkuId        : $($_.SkuId)`nSkuPartNumber: $($_.SkuPartNumber)" }) -join "`n" }

    [PSCustomObject]@{ TenantName=$org.DisplayName; TenantId=$org.Id; UserDisplayName=$user.DisplayName; UserPrincipalName=$user.UserPrincipalName; UserId=$user.Id; DirectRoles=Format-Roles $directAssignments; GroupRoles=Format-Roles $groupAssignments; EligibleRoles=$eligibleRolesStr; TransitiveGroups=Format-Groups $groups; AdministrativeUnits=Format-AUs $administrativeUnits; AUScopedRoles=$auScopedStr; OAuthGrants=$oauthStr; AppRoleAssignments=$appRoleStr; OwnedObjects=Format-OwnedObjects $ownedObjects; OwnedDevices=Format-OwnedObjects $ownedDevices; RegisteredDevices=Format-OwnedObjects $registeredDevices; AuthenticationMethods=$authStr; LicenseDetails=$licStr } | Format-List
}

# =============================================================
# APP
# =============================================================
elseif ($Type -eq "app") {
    $org = Get-MgOrganization
    $sp  = Get-MgServicePrincipal -Filter "DisplayName eq '$Identity'"

    # Intentar resolver el Application Object. En Managed Identities puede no existir.
    $app = $null
    try {
        $appResult = Get-MgApplication -Filter "appId eq '$($sp.AppId)'" -ErrorAction Stop
        if ($appResult -and $appResult.Id) { $app = $appResult }
    } catch {}

    $transitiveMemberOf  = @(Get-MgServicePrincipalTransitiveMemberOf -ServicePrincipalId $sp.Id -All)
    $groups              = @($transitiveMemberOf | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' })
    $administrativeUnits = @($transitiveMemberOf | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.administrativeUnit' })
    $directAssignments   = Get-RoleAssignments -PrincipalId $sp.Id
    $groupAssignments    = @(foreach ($g in $groups) { Get-RoleAssignments -PrincipalId $g.Id })
    $spAssignments       = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id)
    try   { $oauthGrants = @(Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" -ErrorAction Stop) } catch { $oauthGrants = @() }
    $spOwners     = @(Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id)
    $ownedObjects = @(Get-MgServicePrincipalOwnedObject -ServicePrincipalId $sp.Id)

    # Application Object dependiente -- solo si existe
    if ($app -and $app.Id) {
        $appOwners    = @(Get-MgApplicationOwner -ApplicationId $app.Id)
        $reqAccessStr = if (-not $app.RequiredResourceAccess -or $app.RequiredResourceAccess.Count -eq 0) { "(none)" } else {
            ($app.RequiredResourceAccess | ForEach-Object {
                $rid = $_.ResourceAppId
                $rsp = Get-MgServicePrincipal -Filter "appId eq '$rid'"
                foreach ($access in $_.ResourceAccess) {
                    $perm = if ($access.Type -eq "Role") {
                        $rsp.AppRoles | Where-Object { $_.Id -eq $access.Id }
                    } elseif ($access.Type -eq "Scope") {
                        $rsp.Oauth2PermissionScopes | Where-Object { $_.Id -eq $access.Id }
                    }
                    "Resource        : $($rsp.DisplayName)`nResourceAppId   : $rid`nPermissionType  : $($access.Type)`nPermissionName  : $($perm.Value)`nPermissionId    : $($access.Id)`n"
                }
            }) -join "`n"
        }
        $keyCertStr  = if (-not $app.KeyCredentials -or $app.KeyCredentials.Count -eq 0) { "(none)" } else {
            ($app.KeyCredentials | ForEach-Object {
                "DisplayName : $($_.DisplayName)`nKeyId       : $($_.KeyId)`nStart       : $($_.StartDateTime)`nEnd         : $($_.EndDateTime)`nType        : $($_.Type)`nUsage       : $($_.Usage)`n"
            }) -join "`n"
        }
        $passCredStr = if (-not $app.PasswordCredentials -or $app.PasswordCredentials.Count -eq 0) { "(none)" } else {
            ($app.PasswordCredentials | ForEach-Object {
                "DisplayName : $($_.DisplayName)`nKeyId       : $($_.KeyId)`nStart       : $($_.StartDateTime)`nEnd         : $($_.EndDateTime)`n"
            }) -join "`n"
        }
        $appOwnersStr = if ($appOwners.Count -eq 0) { "(none)" } else {
            ($appOwners | ForEach-Object {
                "Id          : $($_.Id)`nDisplayName : $($_.AdditionalProperties.displayName)`nObjectType  : $($_.AdditionalProperties.'@odata.type')"
            }) -join "`n"
        }
    } else {
        # Managed Identity u otro SP sin Application Object asociado
        $appOwnersStr = "(none)"
        $reqAccessStr = "(none)"
        $keyCertStr   = "(none)"
        $passCredStr  = "(none)"
    }

    $graphAppRolesStr = if ($spAssignments.Count -eq 0) { "(none)" } else {
        ($spAssignments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ResourceId) } | ForEach-Object {
            $rsp  = Resolve-ResourceSP $_.ResourceId
            $arId = $_.AppRoleId
            if ($rsp) {
                $appRole = $rsp.AppRoles | Where-Object { $_.Id -eq $arId }
                "Resource        : $($rsp.DisplayName)`nResourceAppId   : $($rsp.AppId)`nDisplayName     : $($appRole.DisplayName)`nDescription     : $($appRole.Description)`nValue           : $($appRole.Value)`nAllowedMembers  : $($appRole.AllowedMemberTypes)`nRoleId          : $($appRole.Id)`n"
            }
        }) -join "`n"
    }
    $oauthStr    = if ($oauthGrants.Count -eq 0) { "(none)" } else {
        ($oauthGrants | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ResourceId) } | ForEach-Object {
            "ConsentType : $($_.ConsentType)`nScope       : $($_.Scope)`nResourceId  : $($_.ResourceId)`n"
        }) -join "`n"
    }
    $spOwnersStr = if ($spOwners.Count -eq 0) { "(none)" } else {
        ($spOwners | ForEach-Object {
            "Id          : $($_.Id)`nDisplayName : $($_.AdditionalProperties.displayName)`nObjectType  : $($_.AdditionalProperties.'@odata.type')"
        }) -join "`n"
    }

    $samlMode       = if ($sp.PreferredSingleSignOnMode) { $sp.PreferredSingleSignOnMode } else { "(none)" }
    $samlThumbprint = "(none)"
    try {
        $samlResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($sp.Id)/PreferredTokenSigningKeyThumbprint" -ErrorAction Stop
        if ($samlResp.value) { $samlThumbprint = $samlResp.value }
    } catch {}

    $assignedStr = "(none)"
    try {
        $assigned = @(Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All -ErrorAction Stop)
        if ($assigned.Count -gt 0) {
            $assignedStr = ($assigned | ForEach-Object {
                "DisplayName : $($_.PrincipalDisplayName)`nType        : $($_.PrincipalType)`nPrincipalId : $($_.PrincipalId)`nAppRoleId   : $($_.AppRoleId)`n"
            }) -join "`n"
        }
    } catch {}

    [PSCustomObject]@{
        TenantName                         = $org.DisplayName
        TenantId                           = $org.Id
        DisplayName                        = $sp.DisplayName
        Id                                 = $sp.Id
        AppId                              = $sp.AppId
        SPType                             = $sp.ServicePrincipalType
        PreferredSingleSignOnMode          = $samlMode
        PreferredTokenSigningKeyThumbprint = $samlThumbprint
        AssignedPrincipals                 = $assignedStr
        DirectRoles                        = Format-Roles $directAssignments
        GroupRoles                         = Format-Roles $groupAssignments
        TransitiveGroups                   = Format-Groups $groups
        AdministrativeUnits                = Format-AUs $administrativeUnits
        GraphAppRoles                      = $graphAppRolesStr
        OAuthGrants                        = $oauthStr
        SPOwners                           = $spOwnersStr
        AppOwners                          = $appOwnersStr
        OwnedObjects                       = Format-OwnedObjects $ownedObjects
        RequiredResourceAccess             = $reqAccessStr
        KeyCredentials                     = $keyCertStr
        PasswordCredentials                = $passCredStr
    } | Format-List
}

# =============================================================
# APPS
# =============================================================
elseif ($Type -eq "apps") {
    if (-not $GraphToken) { throw "[-] -GraphToken es obligatorio para -Type 'apps'" }
    $headers = @{ Authorization = "Bearer $GraphToken" }
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications" -Headers $headers |
        Select-Object -ExpandProperty value |
        Select-Object displayName, appId, notes |
        Format-List
}

# =============================================================
# GROUP
# =============================================================
elseif ($Type -eq "group") {
    $org   = Get-MgOrganization
    $group = Get-MgGroup -Filter "displayName eq '$Identity'"
    if (-not $group) { throw "[-] Group not found: $Identity" }
    $roleAssignments = Get-RoleAssignments -PrincipalId $group.Id
    $owners          = @(Get-MgGroupOwner -GroupId $group.Id)
    try   { $appRoleAssignments = @(Get-MgGroupAppRoleAssignment -GroupId $group.Id) } catch { $appRoleAssignments = @() }
    try   { $transitiveMembers  = @(Get-MgGroupTransitiveMember  -GroupId $group.Id -All) } catch { $transitiveMembers = @() }

    $effectivePermsStr = if ($roleAssignments.Count -eq 0) { "(none)" } else {
        $lines = foreach ($a in ($roleAssignments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.RoleDefinitionId) })) { $role = Resolve-Role $a.RoleDefinitionId; foreach ($perm in $role.RolePermissions) { foreach ($action in $perm.allowedResourceActions) { "RoleName : $($role.DisplayName)`nAction   : $action" } } }
        if ($lines) { $lines -join "`n" } else { "(none)" }
    }
    $ownersStr = if ($owners.Count -eq 0) { "(none)" } else { ($owners | ForEach-Object { $objType = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''; "Id          : $($_.Id)`nDisplayName : $($_.AdditionalProperties.displayName)`nObjectType  : $objType" }) -join "`n" }

    $appRoleStr = if ($appRoleAssignments.Count -eq 0) { "(none)" } else {
        ($appRoleAssignments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ResourceId) } | ForEach-Object {
            try {
                $rsp      = Get-MgServicePrincipal -ServicePrincipalId $_.ResourceId
                $arId     = $_.AppRoleId
                $appRole  = $rsp.AppRoles | Where-Object { $_.Id -eq $arId }
                $roleName = if ($appRole -and $appRole.DisplayName) { $appRole.DisplayName } else { "(unresolved)" }
                "Resource     : $($rsp.DisplayName)`nSPType       : $($rsp.ServicePrincipalType)`nResourceId   : $($_.ResourceId)`nAppRoleId    : $arId`nRoleName     : $roleName"
            } catch {}
        }) -join "`n"
    }

    $membersStr = if ($transitiveMembers.Count -eq 0) { "(none)" } else { ($transitiveMembers | ForEach-Object { $objType = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''; "Id          : $($_.Id)`nDisplayName : $($_.AdditionalProperties.displayName)`nObjectType  : $objType" }) -join "`n" }

    [PSCustomObject]@{ GroupDisplayName=$group.DisplayName; GroupId=$group.Id; MailEnabled=$group.MailEnabled; SecurityEnabled=$group.SecurityEnabled; Visibility=$group.Visibility; GroupTypes=($group.GroupTypes -join ", "); IsAssignableToRole=$group.IsAssignableToRole; MembershipRule=$group.MembershipRule; RoleAssignments=Format-Roles $roleAssignments; EffectivePermissions=$effectivePermsStr; Owners=$ownersStr; AppRoleAssignments=$appRoleStr; TransitiveMembers=$membersStr } | Format-List
}

# =============================================================
# ROLE
# =============================================================
elseif ($Type -eq "role") {
    try {
        $raw  = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$Identity'" -ErrorAction Stop
        $role = $raw.value | Select-Object -First 1
    } catch { $role = $null }
    if (-not $role) { throw "[-] Role not found: $Identity" }
    $activeAssignments = @()
    try { $activeRaw = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($role.id)'" -ErrorAction Stop; $activeAssignments = @($activeRaw.value) } catch {}
    $actionsStr = ($role.rolePermissions | ForEach-Object { foreach ($action in $_.allowedResourceActions) { "Action : $action" } }) -join "`n"
    $activeStr  = if ($activeAssignments.Count -eq 0) { "(none)" } else { ($activeAssignments | ForEach-Object { $pt = Resolve-Principal $_.principalId; "PrincipalType     : $pt`nPrincipalId       : $($_.principalId)`nRoleDefinitionId  : $($_.roleDefinitionId)`nDirectoryScopeId  : $($_.directoryScopeId)" }) -join "`n" }
    [PSCustomObject]@{ RoleDisplayName=$role.displayName; RoleId=$role.id; Description=$role.description; IsBuiltIn=$role.isBuiltIn; IsEnabled=$role.isEnabled; AllowedActions=$actionsStr; ActiveAssignments=$activeStr } | Format-List
}

# =============================================================
# GRAPH
# =============================================================
elseif ($Type -eq "graph") {
    if (-not $GraphToken) { throw "[-] -GraphToken es obligatorio para -Type 'graph'" }
    $ctx    = try { Get-MgContext } catch { $null }
    $claims = Get-JwtPayload -Token $GraphToken
    $identityType   = if ($claims.roles) { "AppOnly / Service Principal" } elseif ($claims.scp) { "Delegated / User" } else { "Unknown" }
    $userIdentity   = if ($claims.upn) { $claims.upn } elseif ($claims.preferred_username) { $claims.preferred_username } elseif ($claims.name) { $claims.name } elseif ($ctx -and $ctx.Account) { $ctx.Account } else { $claims.oid }
    $clientIdentity = if ($claims.appid) { $claims.appid } elseif ($claims.azp) { $claims.azp } elseif ($ctx) { $ctx.ClientId } else { "(unknown)" }
    $expUtc  = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).UtcDateTime } else { $null }
    $iatUtc  = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).UtcDateTime } else { $null }
    $nbfUtc  = if ($claims.nbf) { [DateTimeOffset]::FromUnixTimeSeconds($claims.nbf).UtcDateTime } else { $null }
    $expired = if ($expUtc) { [DateTime]::UtcNow -gt $expUtc } else { $null }
    $onPremSync     = try { if ($claims.idtyp -ne "app") { (Get-MgUser -UserId $claims.oid -Property OnPremisesSyncEnabled).OnPremisesSyncEnabled } else { $null } } catch { $null }
    $onPremLastSync = try { if ($claims.idtyp -ne "app") { (Get-MgUser -UserId $claims.oid -Property OnPremisesLastSyncDateTime).OnPremisesLastSyncDateTime } else { $null } } catch { $null }
    [PSCustomObject]@{ Token="GRAPH"; AuthFlow=$claims.auth_protocol; IdentityType=$identityType; UserIdentity=$userIdentity; UserDisplayName=$claims.name; UserPrincipalName=$claims.upn; PreferredUsername=$claims.preferred_username; UserObjectId=$claims.oid; ClientId=$clientIdentity; ClientAppName=if ($ctx) { $ctx.AppName } else { $claims.app_displayname }; Account=if ($ctx) { $ctx.Account } else { $null }; TenantId=$claims.tid; Audience=$claims.aud; AuthType=if ($ctx) { $ctx.AuthType } else { "UserProvidedAccessToken" }; Roles=($claims.roles -join ", "); Scopes=$claims.scp; OnPremisesSyncEnabled=$onPremSync; OnPremisesLastSyncDateTime=$onPremLastSync; IssuedAt=$iatUtc; NotBefore=$nbfUtc; ExpiresAt=$expUtc; IsExpired=$expired } | Format-List
}

# =============================================================
# ARM
# =============================================================
elseif ($Type -eq "arm") {
    Show-TokenContext -TokenName "arm" -Token $ArmToken
    $arm = $ArmToken; $ctx = Get-AzContext
    try { $sub   = Get-AzSubscription   -ErrorAction Stop } catch { Write-Host "[!] Get-AzSubscription fallo" -ForegroundColor Yellow; $sub = $null }
    try { $res   = Get-AzResource       -ErrorAction Stop } catch { Write-Host "[!] Get-AzResource fallo"     -ForegroundColor Yellow; $res = @() }
    try { $kv    = Get-AzKeyVault       -ErrorAction Stop } catch { Write-Host "[!] Get-AzKeyVault fallo"     -ForegroundColor Yellow; $kv = @() }
    try { $roles = Get-AzRoleAssignment -ErrorAction Stop } catch { Write-Host "[!] Get-AzRoleAssignment fallo" -ForegroundColor Yellow; $roles = @() }

    $kvPerms = foreach ($v in $kv) {
        try { $uri = "https://management.azure.com/subscriptions/$($sub.Id)/resourceGroups/$($v.ResourceGroupName)/providers/Microsoft.KeyVault/vaults/$($v.VaultName)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"; (Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $arm" }).value | ForEach-Object { "VaultName     : $($v.VaultName)`nactions       : [$(($_.actions -join ', '))]`nnotActions    : [$(($_.notActions -join ', '))]`ndataActions   : [$(($_.dataActions -join ', '))]`nnotDataActions: [$(($_.notDataActions -join ', '))]`n" } }
        catch { "Error querying permissions for $($v.VaultName): $($_.Exception.Message)" }
    }
    $kvRoleAssignments = foreach ($v in $kv) {
        $kvScope = "/subscriptions/$($sub.Id)/resourceGroups/$($v.ResourceGroupName)/providers/Microsoft.KeyVault/vaults/$($v.VaultName)"
        $roles | Where-Object { $_.Scope -eq $kvScope -or $kvScope.StartsWith($_.Scope) } | ForEach-Object { $roleDef = Get-AzRoleDefinition -Id $_.RoleDefinitionId; "VaultName        : $($v.VaultName)`nRoleName         : $($_.RoleDefinitionName)`nRoleDefinitionId : $($_.RoleDefinitionId)`nDescription      : $($roleDef.Description)`nScope            : $($_.Scope)`n" }
    }
    $resourceIdsStr = ($res | ForEach-Object {
        $rid = if ($_.ResourceId) { $_.ResourceId } else { $_.Id }
        try {
            $uri = "https://management.azure.com$rid/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $response = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $arm" } -ErrorAction Stop
            $perms = $response.value
            $permStr = if (-not $perms -or @($perms).Count -eq 0) { " | (no permissions returned)" } else {
                $parts = foreach ($entry in @($perms)) { foreach ($cat in @("actions","notActions","dataActions","notDataActions")) { $label = switch ($cat) { "actions" {"Actions"} "notActions" {"NotActions"} "dataActions" {"DataActions"} "notDataActions" {"NotDataActions"} }; $items = $entry.$cat; if (-not $items -or $items.Count -eq 0) { " | $label -> (none)" } else { foreach ($item in $items) { " | $label -> $item" } } } }
                $parts -join "`n"
            }
            "$rid`n$permStr"
        } catch { $sc = $_.Exception.Response.StatusCode.value__; "$rid`n | (permission query failed - HTTP $sc)" }
    }) -join "`n`n"
    $rbacStr = ($roles | ForEach-Object { $condStr = if (-not [string]::IsNullOrWhiteSpace($_.Condition)) { "`nCondition        : $($_.Condition)`nConditionVersion : $($_.ConditionVersion)" } else { "" }; "RoleName         : $($_.RoleDefinitionName)`nRoleDefinitionId : $($_.RoleDefinitionId)`nScope            : $($_.Scope)$condStr`n" }) -join "`n"
    $storagePermsStr = ($res | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" } | ForEach-Object {
        $saScope = if ($_.ResourceId) { $_.ResourceId } else { $_.Id }
        try { $uri = "https://management.azure.com$saScope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"; $response = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $arm" } -ErrorAction Stop; $perms = $response.value; if ($perms -and @($perms).Count -gt 0) { ($perms | ForEach-Object { "Scope         : $saScope`nactions       : [$((($_.actions) -join ', '))]`nnotActions    : [$((($_.notActions) -join ', '))]`ndataActions   : [$((($_.dataActions) -join ', '))]`nnotDataActions: [$((($_.notDataActions) -join ', '))]`n" }) -join "`n" } } catch {}
    }) -join "`n"
    $azFilesStr = ($res | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" } | ForEach-Object { $sa = Get-AzStorageAccount -ResourceGroupName $_.ResourceGroupName -Name $_.Name; $auth = $sa.AzureFilesIdentityBasedAuth; if ($auth) { "StorageAccount          : $($_.Name)`nDirectoryServiceOptions : $($auth.DirectoryServiceOptions)`nDefaultSharePermission  : $($auth.DefaultSharePermission)" } }) -join "`n"

    [PSCustomObject]@{ Identity=$ctx.Account.Id; TenantId=$sub.TenantId; SubscriptionName=$sub.Name; SubscriptionId=$sub.Id; ResourceGroups=(($res | Select-Object -ExpandProperty ResourceGroupName -Unique) -join ", "); Locations=(($res | Select-Object -ExpandProperty Location -Unique) -join ", "); Resources=(($res | Select-Object -ExpandProperty Name -Unique) -join "`n"); ResourceTypes=(($res | Select-Object -ExpandProperty ResourceType -Unique) -join "`n"); ResourceIds=$resourceIdsStr; KeyVaults=(($kv | ForEach-Object { $_.VaultName }) -join ", "); StorageAccounts=(($res | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" } | ForEach-Object { $_.Name }) -join ", "); AzureFilesIdentityBasedAuth=$azFilesStr; RBACRoleAssignments=$rbacStr; KeyVaultRoleAssignments=($kvRoleAssignments -join "`n"); KeyVaultEffectivePermissions=($kvPerms -join "`n"); StoragePermissions=$storagePermsStr } | Format-List
}

# =============================================================
# AU
# =============================================================
elseif ($Type -eq "au") {
    if (-not (Get-MgContext)) { Write-Host "[-] No hay sesion activa de Microsoft Graph." -ForegroundColor Red; exit 1 }
    $auList = @()
    if (Test-IsGuid -Value $Identity) {
        try { $au = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $Identity -ErrorAction Stop; $auList = @($au) } catch { Write-Host "[!] No se pudo resolver la AU con GUID: $Identity" -ForegroundColor Yellow }
    } else {
        try { $resolved = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$Identity'" -ErrorAction Stop; $auList = @($resolved); if ($auList.Count -eq 0) { Write-Host "[-] No se encontro ninguna AU: $Identity" -ForegroundColor Red; exit 1 }; if ($auList.Count -gt 1) { Write-Host "[!] Se encontraron $($auList.Count) AUs. Procesando todas." -ForegroundColor Yellow } } catch { Write-Host "[!] Error: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
    }
    foreach ($au in $auList) {
        $mt = Get-AUMembershipType -AUId $au.Id
        Write-Host "`n[+] AU: $($au.DisplayName) ($($au.Id))  MembershipType: $mt" -ForegroundColor Cyan
        try { $members = @(Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All -ErrorAction Stop); if ($members.Count -eq 0) { Write-Host "[+] No members found." -ForegroundColor Green; continue }; $members | ForEach-Object { $ap = $_.AdditionalProperties; [PSCustomObject]@{ AdministrativeUnit=$au.DisplayName; AdministrativeUnitId=$au.Id; MembershipType=$mt; Id=$_.Id; DisplayName=$ap.displayName; UserPrincipalName=$ap.userPrincipalName; AppId=$ap.appId; ObjectType=$ap.'@odata.type' } } | Format-List } catch { Write-Host "[!] Error: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
    }
}

# =============================================================
# OWNER
# =============================================================
elseif ($Type -eq "owner") {
    if (-not (Get-MgContext)) { Write-Host "[-] No hay sesion activa de Microsoft Graph." -ForegroundColor Red; exit 1 }
    $spList = @()
    if (Test-IsGuid -Value $Identity) {
        try { $sp = Get-MgServicePrincipal -ServicePrincipalId $Identity -ErrorAction Stop; $spList = @($sp) } catch { try { $sp = Get-MgServicePrincipal -Filter "appId eq '$Identity'" -ErrorAction Stop; if ($sp) { $spList = @($sp) } } catch {}; if ($spList.Count -eq 0) { Write-Host "[!] No se pudo resolver el SP: $Identity" -ForegroundColor Yellow } }
    } else {
        try { $resolved = Get-MgServicePrincipal -Filter "displayName eq '$Identity'" -ErrorAction Stop; $spList = @($resolved); if ($spList.Count -eq 0) { Write-Host "[-] No se encontro ningun SP: $Identity" -ForegroundColor Red; exit 1 }; if ($spList.Count -gt 1) { Write-Host "[!] Multiples SPs encontrados. Usa ObjectId para ser especifico." -ForegroundColor Yellow } } catch { Write-Host "[!] Error: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
    }
    foreach ($sp in $spList) {
        Write-Host "`n[+] SP: $($sp.DisplayName) ($($sp.Id))" -ForegroundColor Cyan
        try { $ownedObjects = @(Get-MgServicePrincipalOwnedObject -ServicePrincipalId $sp.Id -All -ErrorAction Stop); if ($ownedObjects.Count -eq 0) { Write-Host "[+] No owned objects found." -ForegroundColor Green; continue }; $ownedObjects | ForEach-Object { $ap = $_.AdditionalProperties; [PSCustomObject]@{ OwnerPrincipal=$sp.DisplayName; PrincipalId=$sp.Id; Id=$_.Id; DisplayName=$ap.displayName; ObjectType=$ap.'@odata.type'; UserPrincipalName=$ap.userPrincipalName; AppId=$ap.appId } } | Format-List } catch { Write-Host "[!] Error: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
    }
}

# =============================================================
# KEYVAULT
# =============================================================
elseif ($Type -eq "keyvault") {
    $kvURI = "https://$VaultName.vault.azure.net"; $apiVer = "7.4"; $headers = @{ Authorization = "Bearer $KeyVaultToken" }; $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    Write-Host "`n== CERTIFICATES ==" -ForegroundColor Cyan
    try {
        $certs = (Invoke-RestMethod -Method GET -Uri "$kvURI/certificates?api-version=$apiVer" -Headers $headers -ErrorAction Stop).value
        if (-not $certs -or $certs.Count -eq 0) { Write-Host "[+] No certificates found." -ForegroundColor Green } else {
            foreach ($cert in $certs) {
                try {
                    $certDetail = Invoke-RestMethod -Method GET -Uri "$($cert.id)?api-version=$apiVer" -Headers $headers -ErrorAction Stop
                    $certName = ($certDetail.id -split "/")[-1]; $x5t = $certDetail.x5t; $kid = $certDetail.kid; $sid = $certDetail.sid; $enabled = $certDetail.attributes.enabled; $nbf = $certDetail.attributes.nbf; $exp = $certDetail.attributes.exp
                    $nbfUTC = if ($nbf) { [DateTimeOffset]::FromUnixTimeSeconds($nbf).UtcDateTime } else { $null }; $expUTC = if ($exp) { [DateTimeOffset]::FromUnixTimeSeconds($exp).UtcDateTime } else { $null }
                    $isTimeValid = ($(if ($nbf) { $now -ge $nbf } else { $true })) -and ($(if ($exp) { $now -le $exp } else { $true }))
                    $keyOps = @(); $keyType = $null; $canSign = $false
                    if ($kid) { try { $keyInfo = Invoke-RestMethod -Method GET -Uri "$kid`?api-version=$apiVer" -Headers $headers -ErrorAction Stop; $keyOps = @($keyInfo.key.key_ops); $keyType = $keyInfo.key.kty; $canSign = $keyOps -contains "sign" } catch {} }
                    $usable = $enabled -and $isTimeValid -and $canSign -and $x5t -and $kid
                    [PSCustomObject]@{ VaultName=$VaultName; CertificateName=$certName; Enabled=$enabled; NotBeforeUTC=$nbfUTC; ExpiresUTC=$expUTC; IsTimeValid=$isTimeValid; x5t=$x5t; kid=$kid; sid=$sid; KeyType=$keyType; KeyOps=($keyOps -join ", "); CanSign=$canSign; UsableForJWTAssertion=$usable } | Format-List
                } catch { Write-Host "[!] Error reading cert $($cert.id): $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
            }
        }
    } catch { Write-Host "[!] Failed to enumerate certificates: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }

    Write-Host "`n== KEYS ==" -ForegroundColor Cyan
    try {
        $keys = (Invoke-RestMethod -Method GET -Uri "$kvURI/keys?api-version=$apiVer" -Headers $headers -ErrorAction Stop).value
        if (-not $keys -or $keys.Count -eq 0) { Write-Host "[+] No keys found." -ForegroundColor Green } else {
            foreach ($k in $keys) {
                try { $keyDetail = Invoke-RestMethod -Method GET -Uri "$($k.kid)?api-version=$apiVer" -Headers $headers -ErrorAction Stop; $keyName = ($k.kid -split "/")[-2]; $enabled = $keyDetail.attributes.enabled; $nbf = $keyDetail.attributes.nbf; $exp = $keyDetail.attributes.exp; $nbfUTC = if ($nbf) { [DateTimeOffset]::FromUnixTimeSeconds($nbf).UtcDateTime } else { $null }; $expUTC = if ($exp) { [DateTimeOffset]::FromUnixTimeSeconds($exp).UtcDateTime } else { $null }; $keyOps = @($keyDetail.key.key_ops); $canSign = $keyOps -contains "sign"; [PSCustomObject]@{ VaultName=$VaultName; KeyName=$keyName; KeyType=$keyDetail.key.kty; Enabled=$enabled; NotBeforeUTC=$nbfUTC; ExpiresUTC=$expUTC; KeyOps=($keyOps -join ", "); CanSign=$canSign; kid=$k.kid } | Format-List } catch { Write-Host "[!] Error reading key $($k.kid): $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
            }
        }
    } catch { Write-Host "[!] Failed to enumerate keys: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }

    Write-Host "`n== SECRETS ==" -ForegroundColor Cyan
    try {
        $secrets = (Invoke-RestMethod -Method GET -Uri "$kvURI/secrets?api-version=$apiVer" -Headers $headers -ErrorAction Stop).value
        if (-not $secrets -or $secrets.Count -eq 0) { Write-Host "[+] No secrets found." -ForegroundColor Green } else {
            foreach ($s in $secrets) {
                try { $secretDetail = Invoke-RestMethod -Method GET -Uri "$($s.id)?api-version=$apiVer" -Headers $headers -ErrorAction Stop; $secretName = ($s.id -split "/")[-2]; $enabled = $secretDetail.attributes.enabled; $nbf = $secretDetail.attributes.nbf; $exp = $secretDetail.attributes.exp; $nbfUTC = if ($nbf) { [DateTimeOffset]::FromUnixTimeSeconds($nbf).UtcDateTime } else { $null }; $expUTC = if ($exp) { [DateTimeOffset]::FromUnixTimeSeconds($exp).UtcDateTime } else { $null }; [PSCustomObject]@{ VaultName=$VaultName; SecretName=$secretName; Enabled=$enabled; NotBeforeUTC=$nbfUTC; ExpiresUTC=$expUTC; ContentType=$secretDetail.contentType; SecretId=$s.id } | Format-List } catch { Write-Host "[!] Error reading secret $($s.id): $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
            }
        }
    } catch { Write-Host "[!] Failed to enumerate secrets: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
}

# =============================================================
# DEVICE
# =============================================================
elseif ($Type -eq "device") {
    if (-not (Get-MgContext)) { Write-Host "[-] No hay sesion activa de Microsoft Graph." -ForegroundColor Red; exit 1 }
    $devices = @()
    $isGuid = [Guid]::Empty
    if ([Guid]::TryParse($Identity, [ref]$isGuid)) {
        try { $d = Get-MgDevice -DeviceId $Identity -ErrorAction Stop; $devices = @($d) } catch {}
        if ($devices.Count -eq 0) { try { $d = Get-MgDevice -Filter "deviceId eq '$Identity'" -ErrorAction Stop; $devices = @($d) } catch {} }
    } else {
        try { $devices = @(Get-MgDevice -Filter "displayName eq '$Identity'" -ErrorAction Stop) } catch {}
    }
    if ($devices.Count -eq 0) { Write-Host "[-] Device not found: $Identity" -ForegroundColor Red; exit 1 }
    foreach ($dev in $devices) {
        $ownersStr = "(none)"
        try { $owners = @(Get-MgDeviceRegisteredOwner -DeviceId $dev.Id -ErrorAction Stop); if ($owners.Count -gt 0) { $ownersStr = ($owners | ForEach-Object { $ap = $_.AdditionalProperties; if ($ap.userPrincipalName) { $ap.userPrincipalName } elseif ($ap.displayName) { $ap.displayName } else { $_.Id } }) -join ", " } } catch {}
        $azureAdJoined = $dev.TrustType -eq "AzureAd"
        [PSCustomObject]@{ DisplayName=$dev.DisplayName; DeviceId=$dev.DeviceId; ObjectId=$dev.Id; TrustType=$dev.TrustType; AzureAdJoined=$azureAdJoined; IsManaged=$dev.IsManaged; IsCompliant=$dev.IsCompliant; OperatingSystem=$dev.OperatingSystem; OSVersion=$dev.OperatingSystemVersion; AccountEnabled=$dev.AccountEnabled; RegisteredOwners=$ownersStr } | Format-List
    }
}

# =============================================================
# STORAGE
# =============================================================
elseif ($Type -eq "storage") {
    $hdrs = @{ "Content-Type"="application/json"; "Authorization"="Bearer $StorageToken"; "x-ms-version"="2017-11-09"; "accept-encoding"="gzip, deflate" }
    Write-Host "`n== CONTAINERS ==" -ForegroundColor Cyan
    $containers = @()
    try {
        $containerURL = "https://$StorageName.blob.core.windows.net/?comp=list"
        $containerResponse = Invoke-WebRequest -Uri $containerURL -Method GET -Headers $hdrs -UseBasicParsing -ErrorAction Stop
        $containerXMLClean = $containerResponse.Content.ToString().TrimStart([char]0xFEFF) -replace '^ï»¿',''
        [xml]$containerXML = $containerXMLClean; $containers = @($containerXML.EnumerationResults.Containers.Container)
        if ($containers.Count -eq 0) { Write-Host "[+] No containers found." -ForegroundColor Green } else { $containers | ForEach-Object { [PSCustomObject]@{ StorageAccount=$StorageName; ContainerName=$_.Name; LastModified=$_.Properties.'Last-Modified'; LeaseStatus=$_.Properties.LeaseStatus; LeaseState=$_.Properties.LeaseState } | Format-List } }
    } catch { Write-Host "[!] Failed to enumerate containers: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
    if ($containers.Count -gt 0) {
        Write-Host "`n== BLOBS ==" -ForegroundColor Cyan
        foreach ($container in $containers) {
            $containerName = $container.Name
            try { $blobURL = "https://$StorageName.blob.core.windows.net/${containerName}?restype=container&comp=list"; $blobResponse = Invoke-WebRequest -Uri $blobURL -Method GET -Headers $hdrs -UseBasicParsing -ErrorAction Stop; $blobXMLClean = $blobResponse.Content.ToString().TrimStart([char]0xFEFF) -replace '^ï»¿',''; [xml]$blobXML = $blobXMLClean; $blobs = @($blobXML.EnumerationResults.Blobs.Blob); if ($blobs.Count -eq 0) { Write-Host "[+] Container '$containerName': no blobs found." -ForegroundColor Green } else { [PSCustomObject]@{ StorageAccount=$StorageName; ContainerName=$containerName; BlobCount=$blobs.Count; BlobNames=($blobs | ForEach-Object { $_.Name }) -join "`n" } | Format-List } } catch { Write-Host "[!] Failed to enumerate blobs in '$containerName': $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow }
        }
    }
}

# =============================================================
# MI
# ARM-only. Visibility-based. No Graph. No Get-Mg*.
# Solo muestra Managed Identities visibles desde el contexto Az actual.
# No representa todas las Managed Identities del tenant.
# =============================================================
elseif ($Type -eq "mi") {
    $azCtx = Get-AzContext
    if (-not $azCtx) {
        Write-Host "[-] -Type mi requiere una sesion Az activa. Ejecuta Connect-AzAccount primero." -ForegroundColor Red
        exit 1
    }

    Write-Host "`n[!] -Type mi es ARM-only. Solo muestra Managed Identities visibles desde el contexto Az actual." -ForegroundColor Yellow
    Write-Host "    No representa todas las Managed Identities del tenant." -ForegroundColor Yellow

    $tenantId = $azCtx.Tenant.Id

    # Get an ARM token from the current context to query effective permissions
    $armTokenForPerms = $null
    try {
        $armTokenForPerms = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -ErrorAction Stop).Token
    } catch {
        Write-Host "[!] No se pudo obtener token ARM para consultar permisos efectivos. CurrentIdentityPermissionsOnAssociatedResources quedara vacio." -ForegroundColor Yellow
    }

    Write-Host "`n[+] Enumerating resources with Get-AzResource -ExpandProperties..." -ForegroundColor Cyan
    try {
        $allResources = @(Get-AzResource -ExpandProperties -ErrorAction Stop)
    } catch {
        Write-Host "[!] Get-AzResource fallo: $($_.Exception.Message -split "`n" | Select-Object -First 1)" -ForegroundColor Yellow
        $allResources = @()
    }

    Write-Host "[+] Found $($allResources.Count) resources. Scanning for Managed Identities..." -ForegroundColor Cyan

    try {
        $allRbac = @(Get-AzRoleAssignment -ErrorAction Stop)
    } catch {
        Write-Host "[!] Get-AzRoleAssignment fallo." -ForegroundColor Yellow
        $allRbac = @()
    }

    # Diccionario deduplcado por PrincipalId
    # Estructura: PrincipalId -> @{ Kind; ClientId; AssociatedResources = List }
    $miMap = @{}

    foreach ($res in $allResources) {
        $resId = if ($res.ResourceId) { $res.ResourceId } else { $res.Id }

        # SystemAssigned
        if ($res.Identity -and
            $res.Identity.Type -match "SystemAssigned" -and
            -not [string]::IsNullOrWhiteSpace($res.Identity.PrincipalId)) {

            $pid = $res.Identity.PrincipalId
            if (-not $miMap.ContainsKey($pid)) {
                $miMap[$pid] = @{
                    Kind                = "SystemAssigned"
                    ClientId            = "(not available - ARM only)"
                    AssociatedResources = [System.Collections.Generic.List[string]]::new()
                }
            }
            if (-not $miMap[$pid].AssociatedResources.Contains($resId)) {
                $miMap[$pid].AssociatedResources.Add($resId)
            }
        }

        # UserAssigned attached: recursos con .Identity.UserAssignedIdentities
        # Las keys son Resource IDs; el valor de cada key tiene PrincipalId y ClientId
        if ($res.Identity -and $res.Identity.UserAssignedIdentities) {
            foreach ($uaKey in $res.Identity.UserAssignedIdentities.Keys) {
                $uaVal = $res.Identity.UserAssignedIdentities[$uaKey]
                $pid   = $uaVal.PrincipalId
                $cid   = if (-not [string]::IsNullOrWhiteSpace($uaVal.ClientId)) { $uaVal.ClientId } else { "(not available)" }
                if ([string]::IsNullOrWhiteSpace($pid)) { continue }
                if (-not $miMap.ContainsKey($pid)) {
                    $miMap[$pid] = @{
                        Kind                = "UserAssigned (attached)"
                        ClientId            = $cid
                        AssociatedResources = [System.Collections.Generic.List[string]]::new()
                    }
                }
                if (-not $miMap[$pid].AssociatedResources.Contains($resId)) {
                    $miMap[$pid].AssociatedResources.Add($resId)
                }
            }
        }
    }

    # UserAssigned standalone: recursos de tipo Microsoft.ManagedIdentity/userAssignedIdentities
    $uaStandalone = @($allResources | Where-Object { $_.ResourceType -eq "Microsoft.ManagedIdentity/userAssignedIdentities" })
    foreach ($ua in $uaStandalone) {
        $uaId = if ($ua.ResourceId) { $ua.ResourceId } else { $ua.Id }
        $pid  = $ua.Properties.principalId
        $cid  = if (-not [string]::IsNullOrWhiteSpace($ua.Properties.clientId)) { $ua.Properties.clientId } else { "(not available)" }
        if ([string]::IsNullOrWhiteSpace($pid)) { continue }
        if (-not $miMap.ContainsKey($pid)) {
            $miMap[$pid] = @{
                Kind                = "UserAssigned (standalone)"
                ClientId            = $cid
                AssociatedResources = [System.Collections.Generic.List[string]]::new()
            }
        }
        if (-not $miMap[$pid].AssociatedResources.Contains($uaId)) {
            $miMap[$pid].AssociatedResources.Add($uaId)
        }
    }

    if ($miMap.Count -eq 0) {
        Write-Host "`n[+] No Managed Identities found in visible ARM resources." -ForegroundColor Green
        exit 0
    }

    $miList = @($miMap.GetEnumerator())
    $total  = $miList.Count
    $idx    = 0

    foreach ($entry in $miList) {
        $idx++
        $pid            = $entry.Key
        $kind           = $entry.Value.Kind
        $cid            = $entry.Value.ClientId
        $assocResources = @($entry.Value.AssociatedResources)

        # AssociatedResources string -- un ResourceId por linea
        $assocStr = if ($assocResources.Count -eq 0) {
            "(not found in visible ARM resources)"
        } else {
            $assocResources -join "`n"
        }

        # RBACAssignments de la Managed Identity
        # Permisos QUE TIENE la MI sobre recursos Azure
        $miRbac  = @($allRbac | Where-Object { $_.ObjectId -eq $pid })
        $rbacStr = if ($miRbac.Count -eq 0) { "(none)" } else {
            ($miRbac | ForEach-Object {
                "RoleName         : $($_.RoleDefinitionName)`nRoleDefinitionId : $($_.RoleDefinitionId)`nScope            : $($_.Scope)`nObjectId         : $($_.ObjectId)"
            }) -join "`n`n"
        }

        # CurrentIdentityPermissionsOnAssociatedResources
        # Permissions held by the current context (authenticated user/SP) on each associated resource
        # Reutiliza la misma logica de consulta de permisos efectivos que -Type arm
        $permBlocks = foreach ($rid in $assocResources) {
            if (-not $armTokenForPerms) {
                "ResourceId     : $rid`n(skipped - ARM token not available)"
                continue
            }
            try {
                $uri      = "https://management.azure.com$rid/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
                $response = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $armTokenForPerms" } -ErrorAction Stop
                $perms    = @($response.value)
                if ($perms.Count -eq 0) {
                    "ResourceId     : $rid`nActions        : (none)`nNotActions     : (none)`nDataActions    : (none)`nNotDataActions : (none)"
                } else {
                    $parts = foreach ($p in $perms) {
                        $actStr    = if ($p.actions       -and @($p.actions).Count -gt 0)       { $p.actions       -join ", " } else { "(none)" }
                        $notActStr = if ($p.notActions    -and @($p.notActions).Count -gt 0)    { $p.notActions    -join ", " } else { "(none)" }
                        $dataStr   = if ($p.dataActions   -and @($p.dataActions).Count -gt 0)   { $p.dataActions   -join ", " } else { "(none)" }
                        $notDatStr = if ($p.notDataActions -and @($p.notDataActions).Count -gt 0) { $p.notDataActions -join ", " } else { "(none)" }
                        "ResourceId     : $rid`nActions        : $actStr`nNotActions     : $notActStr`nDataActions    : $dataStr`nNotDataActions : $notDatStr"
                    }
                    $parts -join "`n"
                }
            } catch {
                $sc = $_.Exception.Response.StatusCode.value__
                "ResourceId     : $rid`n(permission query failed - HTTP $sc)"
            }
        }

        $permStr = if (-not $permBlocks -or @($permBlocks).Count -eq 0) { "(none)" } else {
            (@($permBlocks)) -join "`n`n"
        }

        Write-Host "`n-- Managed Identity [$idx/$total] --" -ForegroundColor Cyan
        [PSCustomObject]@{
            ManagedIdentityKind                             = $kind
            PrincipalId                                     = $pid
            ClientId                                        = $cid
            TenantId                                        = $tenantId
            AssociatedResources                             = $assocStr
            RBACAssignments                                 = $rbacStr
            CurrentIdentityPermissionsOnAssociatedResources = $permStr
        } | Format-List
    }

    Write-Host "[+] Done. $total Managed Identity/ies found." -ForegroundColor Green
}
