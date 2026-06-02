# -----------------------------------------------------------------------------
# get-token.ps1 - Access token acquisition
# Usage (dot-sourcing required):
#
#   . .\get_token.ps1 -Identity "user@tenant.com" -TenantId "<ID>" `
#                     -Scope graph -RefreshToken $refresh_token `
#                     -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
#
# -----------------------------------------------------------------------------
# REFERENCE CLIENT IDs
# -----------------------------------------------------------------------------
#
#   RefreshToken (FOCI)  →  d3590ed6-52b3-4102-aeff-aad2292ab01c  (Microsoft Edge)
#   ROPC / Password      →  1950a258-227b-4e31-a9cf-717495945fc2  (Azure PowerShell)
#   DeviceCode           →  9ba1a5c7-f17a-4de9-a1f1-6178c8d51223  (Microsoft Authenticator)
#
# -----------------------------------------------------------------------------

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Help,

    [Parameter()]
    [string]$Identity,

    [Parameter()]
    [string]$TenantId = "common",

    [Parameter()]
    [ValidateSet("graph", "arm", "keyvault", "storage")]
    [string]$Scope,

    [Parameter()]
    [string]$ClientId,

    [Parameter()] [string]$RefreshToken,
    [Parameter()] [string]$ClientSecret,
    [Parameter()] [string]$CertPath,
    [Parameter()] [switch]$DeviceCode,
    [Parameter()] [string]$Password
)

function Show-Help {
    Write-Host @"

get_token.ps1 -- Retrieves access tokens for Microsoft Entra ID and Azure.
Authenticates and stores the token in a global variable, connecting the corresponding session.

USAGE:
  . .\get_token.ps1 -Identity "user@tenant.com|app_id" -TenantId "tenant_id" -Scope "scope" -ClientId "client_id" [flow]

SCOPES:
  graph      -> `$Graph         (https://graph.microsoft.com)
  arm        -> `$ARM           (https://management.azure.com)
  keyvault   -> `$KeyVault      (https://vault.azure.net)
  storage    -> `$AzureStorage  (https://storage.azure.com)

FLOWS:
  -RefreshToken `$refresh_token
  -Password     "password"        (ROPC — does not support MFA)
  -DeviceCode                     (interactive browser flow)
  -ClientSecret "secret"          (app-only)
  -CertPath     "C:\cert.pfx"    (app-only)
  -SignedJWT    `$signedJWT       (app-only — client_assertion signed externally e.g. via Key Vault)

FOCI CLIENT IDs REFERENCE:
  d3590ed6-52b3-4102-aeff-aad2292ab01c  Microsoft Edge                  (graph, arm, keyvault, storage)
  1950a258-227b-4e31-a9cf-717495945fc2  Azure PowerShell                (graph, arm, keyvault)
  9ba1a5c7-f17a-4de9-a1f1-6178c8d51223  Microsoft Intune Company Portal (graph)
  00b41c95-dab0-4487-9791-b9d2c32c80f2  Office 365 Management           (graph, arm, keyvault, storage)
  04b07795-8ddb-461a-bbee-02f9e1bf7b46  Azure CLI                       (graph, arm, keyvault)
  d3590ed6-52b3-4102-aeff-aad2292ab01c  Microsoft Office                (graph)

EXAMPLES:
  . .\get_token.ps1 -Identity "user@tenant.com" -TenantId "tenant_id" -Scope graph    -RefreshToken `$refresh_token -ClientId "client_id"
  . .\get_token.ps1 -Identity "user@tenant.com" -TenantId "tenant_id" -Scope arm      -Password "password"         -ClientId "client_id"
  . .\get_token.ps1 -Identity "user@tenant.com" -TenantId "tenant_id" -Scope storage  -Password "password"         -ClientId "client_id"
  . .\get_token.ps1 -TenantId "tenant_id"       -Scope graph          -DeviceCode                                  -ClientId "client_id"
  . .\get_token.ps1 -Identity "app_id"          -TenantId "tenant_id" -Scope arm      -CertPath "C:\cert.pfx"     -ClientId "client_id"
  . .\get_token.ps1 -Identity "app_id"          -TenantId "tenant_id" -Scope graph    -SignedJWT `$signedJWT       -ClientId "client_id"

"@ -ForegroundColor Cyan
}

if ($Help -or -not $Scope -or -not $ClientId) { Show-Help; return }

if (-not $RefreshToken -and -not $ClientSecret -and -not $CertPath -and -not $DeviceCode -and -not $Password) {
    Write-Host "[-] Provide one authentication method: -RefreshToken, -ClientSecret, -CertPath, -DeviceCode, or -Password." -ForegroundColor Red
    return
}

function Get-JwtClaims {
    param([string]$Token)
    try {
        $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload)) | ConvertFrom-Json
    } catch { $null }
}

function Request-AccessToken {
    param([string]$Audience, [string]$RefreshToken, [string]$TenantId, [string]$ClientId)
    $body = @{
        client_id     = $ClientId
        scope         = "$Audience offline_access"
        refresh_token = $RefreshToken
        grant_type    = "refresh_token"
    }
    $response = Invoke-RestMethod -UseBasicParsing -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ErrorAction Stop
    if ($response.refresh_token) {
        Set-Variable -Name "refresh_token" -Value $response.refresh_token -Scope Global
        Write-Host "[+] refresh_token updated in `$refresh_token" -ForegroundColor Green
    }
    return $response.access_token
}

function Request-AccessTokenClientSecret {
    param([string]$Audience, [string]$AppId, [string]$ClientSecret, [string]$TenantId)
    $body = @{
        client_id     = $AppId
        client_secret = $ClientSecret
        scope         = $Audience
        grant_type    = "client_credentials"
    }
    $response = Invoke-RestMethod -UseBasicParsing -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ErrorAction Stop
    return $response.access_token
}

function Request-AccessTokenCert {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
          [string]$Audience, [string]$AppId, [string]$TenantId)

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $jwtAudience   = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $certHash      = ([System.Convert]::ToBase64String($Certificate.GetCertHash())) -replace '\+','-' -replace '/','_' -replace '='
    $epoch = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
    $now   = (Get-Date).ToUniversalTime()
    $nbf   = [math]::Round((New-TimeSpan -Start $epoch -End $now).TotalSeconds, 0)
    $exp   = [math]::Round((New-TimeSpan -Start $epoch -End $now.AddMinutes(2)).TotalSeconds, 0)

    $header  = @{ alg = "RS256"; typ = "JWT"; x5t = $certHash }
    $payload = @{ aud = $jwtAudience; exp = $exp; iss = $AppId; jti = [guid]::NewGuid().ToString(); nbf = $nbf; sub = $AppId }

    function ConvertTo-B64Url { param([string]$Json)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
        [System.Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '='
    }

    $b64Header  = ConvertTo-B64Url ($header  | ConvertTo-Json -Compress)
    $b64Payload = ConvertTo-B64Url ($payload | ConvertTo-Json -Compress)
    $unsigned   = "$b64Header.$b64Payload"
    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $signedBytes = $privateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signature = ([System.Convert]::ToBase64String($signedBytes)) -replace '\+','-' -replace '/','_' -replace '='
    $signedJwt = "$unsigned.$signature"

    $body = @{
        client_id             = $AppId
        client_assertion      = $signedJwt
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope                 = $Audience
        grant_type            = "client_credentials"
    }
    $response = Invoke-RestMethod -UseBasicParsing -Method POST -Uri $tokenEndpoint `
        -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } `
        -Body $body -ErrorAction Stop
    return $response.access_token
}

function Request-AccessTokenDeviceCode {
    param([string]$Audience, [string]$ClientId, [string]$TenantId)

    $scopeWithOffline = "$Audience offline_access"
    $deviceResponse = Invoke-RestMethod -UseBasicParsing -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -Body @{ client_id = $ClientId; scope = $scopeWithOffline } -ErrorAction Stop

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  DEVICE CODE FLOW"                      -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  1. Open this URL in your browser:"     -ForegroundColor White
    Write-Host "     $($deviceResponse.verification_uri)" -ForegroundColor Cyan
    Write-Host "  2. Enter this code:"                   -ForegroundColor White
    Write-Host "     $($deviceResponse.user_code)"        -ForegroundColor Green
    Write-Host "  Expires in: $($deviceResponse.expires_in) seconds" -ForegroundColor DarkGray
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""

    $interval = $deviceResponse.interval; $expiresIn = $deviceResponse.expires_in; $elapsed = 0; $tokenResponse = $null

    while ($elapsed -lt $expiresIn) {
        Start-Sleep -Seconds $interval; $elapsed += $interval
        try {
            $tokenResponse = Invoke-RestMethod -UseBasicParsing -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body @{ client_id = $ClientId; grant_type = "urn:ietf:params:oauth:grant-type:device_code"; device_code = $deviceResponse.device_code; scope = $scopeWithOffline } -ErrorAction Stop
            break
        } catch {
            $errBody = $null
            try { $errStream = $_.Exception.Response.GetResponseStream(); $reader = New-Object System.IO.StreamReader($errStream); $errBody = $reader.ReadToEnd() | ConvertFrom-Json } catch {}
            $errCode = if ($errBody.error) { $errBody.error } else { $_.Exception.Message }
            if ($errCode -eq "authorization_pending")      { Write-Host "[*] Waiting for authentication..." -ForegroundColor DarkGray }
            elseif ($errCode -eq "authorization_declined") { Write-Host "[-] The user cancelled authentication." -ForegroundColor Red; return $null }
            elseif ($errCode -eq "expired_token")          { Write-Host "[-] The device code expired." -ForegroundColor Red; return $null }
            elseif ($errCode -eq "bad_verification_code")  { Write-Host "[-] Invalid device code." -ForegroundColor Red; return $null }
            else { Write-Host "[!] Polling error ($errCode)" -ForegroundColor Yellow }
        }
    }

    if (-not $tokenResponse) { Write-Host "[-] Timed out waiting for authentication." -ForegroundColor Red; return $null }

    if ($tokenResponse.refresh_token) {
        Set-Variable -Name "refresh_token" -Value $tokenResponse.refresh_token -Scope Global
        Write-Host "[+] refresh_token saved in `$refresh_token" -ForegroundColor Green
    } else {
        Write-Host "[!] The endpoint did not return a refresh_token." -ForegroundColor Yellow
    }
    return $tokenResponse.access_token
}

function Request-AccessTokenROPC {
    param([string]$Audience, [string]$Username, [string]$Password, [string]$TenantId, [string]$ClientId)
    $body = @{
        client_id  = $ClientId
        scope      = "$Audience offline_access"
        username   = $Username
        password   = $Password
        grant_type = "password"
    }
    $response = Invoke-RestMethod -UseBasicParsing -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ErrorAction Stop
    if ($response.refresh_token) {
        Set-Variable -Name "refresh_token" -Value $response.refresh_token -Scope Global
        Write-Host "[+] refresh_token saved in `$refresh_token" -ForegroundColor Green
    } else { Write-Host "[!] The endpoint did not return a refresh_token." -ForegroundColor Yellow }
    return $response.access_token
}

# ---------------------------------------------
# AUDIENCE / VARIABLE MAP
# ---------------------------------------------
$audienceMap = @{
    graph    = "https://graph.microsoft.com/.default"
    arm      = "https://management.azure.com/.default"
    keyvault = "https://vault.azure.net/.default"
}
$variableMap = @{
    graph    = "Graph"
    arm      = "ARM"
    keyvault = "KeyVault"
    storage  = "AzureStorage"
}

# ---------------------------------------------
# TOKEN ACQUISITION
# ---------------------------------------------
$audience = if ($Scope -eq "storage") {
    if ($RefreshToken -or $Password -or $DeviceCode) {
        "https://storage.azure.com/user_impersonation"  # delegated user flow
    } else {
        "https://storage.azure.com/.default"            # app-only flow
    }
} else {
    $audienceMap[$Scope]
}
Write-Host "`n[*] Requesting token - Scope: $Scope ..." -ForegroundColor Cyan

$accessToken = $null
$authFlow    = $null

try {
    if ($RefreshToken) {
        $authFlow    = "RefreshToken"
        $accessToken = Request-AccessToken -Audience $audience -RefreshToken $RefreshToken -TenantId $TenantId -ClientId $ClientId
    } elseif ($ClientSecret) {
        $authFlow    = "ClientSecret"
        $accessToken = Request-AccessTokenClientSecret -Audience $audience -AppId $Identity -ClientSecret $ClientSecret -TenantId $TenantId
    } elseif ($CertPath) {
        $authFlow    = "Certificate"
        if (-not (Test-Path $CertPath)) { Write-Host "[-] Certificate not found at: $CertPath" -ForegroundColor Red; return }
        $cert        = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $CertPath
        $accessToken = Request-AccessTokenCert -Certificate $cert -Audience $audience -AppId $Identity -TenantId $TenantId
    } elseif ($DeviceCode) {
        $authFlow    = "DeviceCode"
        $accessToken = Request-AccessTokenDeviceCode -Audience $audience -ClientId $ClientId -TenantId $TenantId
        if (-not $accessToken) { return }
    } elseif ($Password) {
        $authFlow    = "ROPC"
        if (-not $Identity) { Write-Host "[-] -Identity (UPN) is required with -Password." -ForegroundColor Red; return }
        $accessToken = Request-AccessTokenROPC -Audience $audience -Username $Identity -Password $Password -TenantId $TenantId -ClientId $ClientId
    }
} catch {
    Write-Host "[-] Error acquiring token ($authFlow): $($_.Exception.Message)" -ForegroundColor Red
    return
}

if (-not $accessToken) { Write-Host "[-] The endpoint did not return access_token." -ForegroundColor Red; return }

Write-Host "[+] Flow used: $authFlow" -ForegroundColor DarkGray

$varName = $variableMap[$Scope]
Set-Variable -Name $varName -Value $accessToken -Scope Global
Write-Host "[+] Token saved in `$$varName" -ForegroundColor Green

$claims = Get-JwtClaims -Token $accessToken

# ---------------------------------------------
# SESSION CONNECTION BY SCOPE
# ---------------------------------------------
$authenticated = $false

if ($Scope -eq "graph") {
    Write-Host "[*] Connecting to Microsoft Graph ..." -ForegroundColor Cyan
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        if ($ClientSecret) {
            $secSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $creds     = New-Object System.Management.Automation.PSCredential($Identity, $secSecret)
            Connect-MgGraph -ClientSecretCredential $creds -TenantId $TenantId -ErrorAction Stop
        } elseif ($CertPath) {
            Connect-MgGraph -Certificate $cert -ClientId $Identity -TenantId $TenantId -ErrorAction Stop
        } else {
            Connect-MgGraph -AccessToken ($accessToken | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome -ErrorAction Stop
        }
        Write-Host "[+] Connect-MgGraph OK" -ForegroundColor Green
        $authenticated = $true
    } catch {
        Write-Host "[-] Connect-MgGraph failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

elseif ($Scope -eq "arm") {
    Write-Host "[*] Connecting to Azure (ARM) ..." -ForegroundColor Cyan
    try {
        Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
        if ($ClientSecret) {
            $secSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $creds     = New-Object System.Management.Automation.PSCredential($Identity, $secSecret)
            Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant $TenantId -ErrorAction Stop | Out-Null
        } elseif ($CertPath) {
            Connect-AzAccount -ServicePrincipal -ApplicationId $Identity -Tenant $TenantId -CertificatePath $CertPath -ErrorAction Stop | Out-Null
        } else {
            Connect-AzAccount -AccessToken $accessToken -AccountId $Identity -Tenant $TenantId -ErrorAction Stop | Out-Null
        }
        Write-Host "[+] Connect-AzAccount (ARM) OK" -ForegroundColor Green
        $authenticated = $true
    } catch {
        Write-Host "[-] Connect-AzAccount (ARM) failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

elseif ($Scope -eq "keyvault") {
    $existingARM = Get-Variable -Name "ARM" -Scope Global -ErrorAction SilentlyContinue
    if (-not $existingARM -or -not $existingARM.Value) {
        Write-Host "[*] `$ARM not found - acquiring ARM token automatically ..." -ForegroundColor Yellow
        try {
            $armAudience = $audienceMap["arm"]
            $armToken = if ($RefreshToken)   { Request-AccessToken -Audience $armAudience -RefreshToken $RefreshToken -TenantId $TenantId -ClientId $ClientId }
                        elseif ($ClientSecret) { Request-AccessTokenClientSecret -Audience $armAudience -AppId $Identity -ClientSecret $ClientSecret -TenantId $TenantId }
                        elseif ($CertPath)     { Request-AccessTokenCert -Certificate $cert -Audience $armAudience -AppId $Identity -TenantId $TenantId }
                        elseif ($Password)     { Request-AccessTokenROPC -Audience $armAudience -Username $Identity -Password $Password -TenantId $TenantId -ClientId $ClientId }
            Set-Variable -Name "ARM" -Value $armToken -Scope Global
            Write-Host "[+] ARM token saved in `$ARM" -ForegroundColor Green
        } catch {
            Write-Host "[-] Could not acquire ARM token: $($_.Exception.Message)" -ForegroundColor Red
            $armToken = $null
        }
    } else {
        $armToken = $existingARM.Value
        Write-Host "[*] Using existing `$ARM token from the current session" -ForegroundColor Cyan
    }

    if ($armToken) {
        Write-Host "[*] Connecting to Azure with ARM + Key Vault token ..." -ForegroundColor Cyan
        try {
            Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
            Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
            Connect-AzAccount -AccessToken $armToken -KeyVaultAccessToken $accessToken `
                -AccountId $Identity -Tenant $TenantId -ErrorAction Stop | Out-Null
            Write-Host "[+] Connect-AzAccount (ARM + KeyVault) OK" -ForegroundColor Green
            $authenticated = $true
        } catch {
            Write-Host "[-] Connect-AzAccount (KeyVault) failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

elseif ($Scope -eq "storage") {
    Write-Host "[*] Storage token saved in `$AzureStorage - ready for manual REST calls." -ForegroundColor Cyan
    Write-Host "    Example usage:" -ForegroundColor DarkGray
    Write-Host '    $URL = "https://<storageaccount>.blob.core.windows.net/?comp=list"' -ForegroundColor DarkGray
    Write-Host '    Invoke-RestMethod -Method GET -Uri $URL -Headers @{' -ForegroundColor DarkGray
    Write-Host '        Authorization  = "Bearer $AzureStorage"' -ForegroundColor DarkGray
    Write-Host '        "x-ms-version" = "2017-11-09"' -ForegroundColor DarkGray
    Write-Host '    }' -ForegroundColor DarkGray
}

# ---------------------------------------------
# FINAL SUMMARY
# ---------------------------------------------
$expUtc  = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).UtcDateTime } else { $null }
$iatUtc  = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).UtcDateTime } else { $null }
$expired = if ($expUtc) { [DateTime]::UtcNow -gt $expUtc } else { "?" }

$resolvedIdentity = if ($claims.upn)                   { $claims.upn }
                    elseif ($claims.preferred_username) { $claims.preferred_username }
                    elseif ($claims.name)               { $claims.name }
                    else                               { $Identity }

if ($Scope -eq "graph" -and $authenticated) {
    $ctx    = try { Get-MgContext } catch { $null }
    $claims = Get-JwtClaims -Token $accessToken

    $identityType   = if ($claims.roles) { "AppOnly / Service Principal" } elseif ($claims.scp) { "Delegated / User" } else { "Unknown" }
    $userIdentity   = if ($claims.upn) { $claims.upn } elseif ($claims.preferred_username) { $claims.preferred_username } elseif ($claims.name) { $claims.name } elseif ($ctx -and $ctx.Account) { $ctx.Account } else { $claims.oid }
    $clientIdentity = if ($claims.appid) { $claims.appid } elseif ($claims.azp) { $claims.azp } elseif ($ctx) { $ctx.ClientId } else { "(unknown)" }
    $expUtc  = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).UtcDateTime } else { $null }
    $iatUtc  = if ($claims.iat) { [DateTimeOffset]::FromUnixTimeSeconds($claims.iat).UtcDateTime } else { $null }
    $nbfUtc  = if ($claims.nbf) { [DateTimeOffset]::FromUnixTimeSeconds($claims.nbf).UtcDateTime } else { $null }
    $expired = if ($expUtc) { [DateTime]::UtcNow -gt $expUtc } else { $null }

    $onPremSync     = try { (Get-MgUser -UserId $claims.oid -Property OnPremisesSyncEnabled -ErrorAction SilentlyContinue).OnPremisesSyncEnabled } catch { $null }
    $onPremLastSync = try { (Get-MgUser -UserId $claims.oid -Property OnPremisesLastSyncDateTime -ErrorAction SilentlyContinue).OnPremisesLastSyncDateTime } catch { $null }

    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan

    [PSCustomObject]@{
        Token                      = "GRAPH"
        AuthFlow                   = $authFlow
        Variable                   = "`$$varName"
        IdentityType               = $identityType
        UserIdentity               = $userIdentity
        UserDisplayName            = $claims.name
        UserPrincipalName          = $claims.upn
        UserObjectId               = $claims.oid
        ClientId                   = $clientIdentity
        ClientAppName              = if ($ctx) { $ctx.AppName } else { $claims.app_displayname }
        Account                    = if ($ctx) { $ctx.Account } else { $null }
        TenantId                   = $claims.tid
        Audience                   = $claims.aud
        AuthType                   = if ($ctx) { $ctx.AuthType } else { $null }
        Roles                      = if ($claims.roles) { ($claims.roles -join ", ") } else { "(none)" }
        Scopes                     = $claims.scp
        OnPremisesSyncEnabled      = $onPremSync
        OnPremisesLastSyncDateTime = $onPremLastSync
        IssuedAt                   = $iatUtc
        NotBefore                  = $nbfUtc
        ExpiresAt                  = $expUtc
        IsExpired                  = $expired
        Authenticated              = $authenticated
    } | Format-List
} else {
    Write-Host "`n==============================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    [PSCustomObject]@{
        Scope         = $Scope.ToUpper()
        AuthFlow      = $authFlow
        Variable      = "`$$varName"
        Identity      = $Identity
        ResolvedAs    = $resolvedIdentity
        TenantId      = $TenantId
        Audience      = $claims.aud
        ClientId      = $claims.appid
        UserObjectId  = $claims.oid
        IssuedAt      = $iatUtc
        ExpiresAt     = $expUtc
        IsExpired     = $expired
        Authenticated = $authenticated
    } | Format-List
}
