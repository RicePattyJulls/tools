# =============================================================================
# recon.ps1
# Merged: Identity Enumeration + Policy Analysis for Microsoft Entra ID
# =============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("enum","search")]
    [string]$Mode,

    [Parameter()] [string]$Query,
    [Parameter()] [string]$CachePath,
    [Parameter()] [switch]$Live,
    [Parameter()] [switch]$Deep,
    [Parameter()] [int]$Threshold = 20,
    [Parameter()] [switch]$OutputCsv,
    [Parameter()] [switch]$Correlacion,

    [Parameter()] [string]$Identity,

    [Parameter()]
    [ValidateSet("user","sp","auto")]
    [string]$Type = "auto",

    [Parameter()] [switch]$AuthMeth,
    [Parameter()] [string]$AuthType,
    [Parameter()] [switch]$Tenant,
    [Parameter()] [switch]$CAP,
    [Parameter()] [switch]$Detailed,
    [Parameter()] [switch]$Raw,
    [Parameter()] [string]$OutputPath,
    [Parameter()] [switch]$ResolveIds = $true,
    [Parameter()] [switch]$Help
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$script:OutputBuffer = [System.Collections.Generic.List[string]]::new()

# =============================================================================
# HELP
# =============================================================================
function Show-Help {
    Write-Host @"

recon.ps1 -- Identity Enumeration + Policy Analysis for Microsoft Entra ID

USAGE:

  -- Identity Enumeration
  .\recon.ps1 -Mode enum
  .\recon.ps1 -Mode enum -Threshold 30
  .\recon.ps1 -Mode enum -Correlacion
  .\recon.ps1 -Mode search -Query "user_display_name"
  .\recon.ps1 -Mode search -Query "object_id_or_guid"
  .\recon.ps1 -Mode search -Query "app_name" -Live
  .\recon.ps1 -Mode search -Query "partial_name" -Live -Deep
  .\recon.ps1 -Mode search -Query "group_name" -CachePath "C:\lab\identity_enum_tenant_name"

  -- Policy Analysis
  .\recon.ps1 -AuthMeth
  .\recon.ps1 -AuthMeth -AuthType TAP
  .\recon.ps1 -Tenant
  .\recon.ps1 -Tenant -Detailed
  .\recon.ps1 -Identity "user@tenant.com" -CAP
  .\recon.ps1 -Identity "user@tenant.com" -CAP -Detailed
  .\recon.ps1 -Identity "sp_name" -Type sp -CAP
  .\recon.ps1 -Identity "sp_name" -Type sp -CAP -OutputPath ".\out.txt"
  .\recon.ps1 -Identity "sp_name" -Type auto -CAP -Raw

MODES:
  enum      Enumerates tenant identities and generates TXT/CSV cache.
  search    Searches local CSV cache and optionally queries Graph with -Live.

IDENTITY OPTIONS:
  -Correlacion   Exports full Application registration details to XML.
  -Live          Queries Graph live if no local cache result is found.
  -Deep          Enables broad Graph searches (-All). Can be slow on large tenants.
  -CachePath     Custom cache folder path. Auto-detected if omitted.
  -Threshold     Threshold for separating large result sets. Default: 20.

POLICY OPTIONS:
  -AuthMeth      Enumerates all enabled CAPs and authentication methods.
  -AuthType      Optional detail mode: TAP, X509, FIDO2, MicrosoftAuthenticator, Email, SMS.
  -Tenant        Enumerates Cross-Tenant Access Policies.
  -CAP           Evaluates Conditional Access Policies for -Identity.
  -Identity      UPN, ObjectId, AppId, or DisplayName of a user or service principal.
  -Type          user | sp | auto. Default: auto.
  -Detailed      Shows additional policy fields.
  -Raw           Shows full Graph objects.
  -OutputPath    Saves output to a TXT file.
  -ResolveIds    Resolves GUIDs to readable names. Enabled by default.
  -Help          Shows this help.

RECOMMENDED SCOPES:
  Directory.Read.All, Organization.Read.All, Application.Read.All,
  Group.Read.All, Policy.Read.All

"@ -ForegroundColor Cyan
}

# =============================================================================
# SHARED OUTPUT HELPERS
# =============================================================================
function Write-Info  { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan   ; $script:OutputBuffer.Add("[*] $Msg") }
function Write-Ok    { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green  ; $script:OutputBuffer.Add("[+] $Msg") }
function Write-Warn  { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow ; $script:OutputBuffer.Add("[!] $Msg") }
function Write-Err   { param([string]$Msg) Write-Host "[-] $Msg" -ForegroundColor Red    ; $script:OutputBuffer.Add("[-] $Msg") }

function Write-Obj {
    param([object]$Obj)
    $text = $Obj | Format-List | Out-String
    Write-Host $text
    $script:OutputBuffer.Add($text)
}

function Write-Sep {
    param([string]$Title = "")
    $line = if ($Title) { "`n== $Title " + ("=" * [Math]::Max(2, 50 - $Title.Length)) } else { "-" * 55 }
    Write-Host $line -ForegroundColor DarkCyan
    $script:OutputBuffer.Add($line)
}

# =============================================================================
# SHARED UTILITIES
# =============================================================================
function Test-IsGuid {
    param([string]$Value)
    $g = [Guid]::Empty
    return [Guid]::TryParse($Value, [ref]$g)
}

function Test-IsUPN {
    param([string]$Value)
    return $Value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$'
}

$Global:ObjectCache = @{}

function Resolve-Object {
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    if ($Id -in @("All","None","Office365","MicrosoftAdminPortals","AllTrusted","GuestsOrExternalUsers")) { return $Id }
    if ($Global:ObjectCache.ContainsKey($Id)) { return $Global:ObjectCache[$Id] }

    try { $loc = Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Id -ErrorAction Stop; if ($loc) { $r = "[LOC] $($loc.DisplayName)"; $Global:ObjectCache[$Id] = $r; return $r } } catch {}
    if (-not (Test-IsGuid $Id)) { $Global:ObjectCache[$Id] = $Id; return $Id }
    try { $u  = Get-MgUser             -UserId            $Id -ErrorAction Stop; $r = "[USER] $($u.UserPrincipalName)";  $Global:ObjectCache[$Id] = $r; return $r } catch {}
    try { $g  = Get-MgGroup            -GroupId           $Id -ErrorAction Stop; $r = "[GROUP] $($g.DisplayName)";        $Global:ObjectCache[$Id] = $r; return $r } catch {}
    try { $sp = Get-MgServicePrincipal -Filter "appId eq '$Id'"  -ErrorAction Stop; if ($sp) { $r = "[APP] $($sp.DisplayName)"; $Global:ObjectCache[$Id] = $r; return $r } } catch {}
    try { $sp = Get-MgServicePrincipal -ServicePrincipalId $Id  -ErrorAction Stop; $r = "[SP] $($sp.DisplayName)";         $Global:ObjectCache[$Id] = $r; return $r } catch {}
    try { $a  = Get-MgApplication      -ApplicationId     $Id  -ErrorAction Stop; $r = "[APPREG] $($a.DisplayName)";      $Global:ObjectCache[$Id] = $r; return $r } catch {}
    try { $ro = Get-MgDirectoryRole    -DirectoryRoleId   $Id  -ErrorAction Stop; $r = "[ROLE] $($ro.DisplayName)";        $Global:ObjectCache[$Id] = $r; return $r } catch {}
    try { $au = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $Id -ErrorAction Stop; $r = "[AU] $($au.DisplayName)"; $Global:ObjectCache[$Id] = $r; return $r } catch {}

    $Global:ObjectCache[$Id] = $Id
    return $Id
}

function Resolve-Collection {
    param([object[]]$Ids, [bool]$DoResolve = $true)
    if (-not $Ids) { return "" }
    if ($DoResolve) { return ($Ids | ForEach-Object { Resolve-Object ([string]$_) } | Where-Object { $_ }) -join ", " }
    return ($Ids -join ", ")
}

# =============================================================================
# GRAPH SESSION VALIDATION
# =============================================================================
function Assert-GraphSession {
    param(
        [ValidateSet("IdentityEnum","Correlation","Policy","SearchLive","Basic")]
        [string]$Context = "Basic"
    )

    $ctx = Get-MgContext
    if (-not $ctx) {
        Write-Err "No active Microsoft Graph session."
        Write-Host "    Run: Connect-MgGraph -Scopes 'Directory.Read.All'" -ForegroundColor Yellow
        exit 1
    }

    $recommended = switch ($Context) {
        "IdentityEnum" { @("Directory.Read.All","Organization.Read.All","Application.Read.All","Group.Read.All") }
        "Correlation"  { @("Application.Read.All") }
        "Policy"       { @("Policy.Read.All","Directory.Read.All","Group.Read.All","Application.Read.All") }
        "SearchLive"   { @("Directory.Read.All","Application.Read.All","Group.Read.All") }
        default        { @() }
    }

    if ($recommended.Count -gt 0) {
        $missing = $recommended | Where-Object { $ctx.Scopes -notcontains $_ }
        if ($missing) {
            Write-Warn "Recommended scopes not found in token for $Context`: $($missing -join ', ')"
            Write-Warn "Access may still work via assigned roles (e.g. Global Reader). Continuing..."
        }
    }

    return $ctx
}

# =============================================================================
# IDENTITY RESOLVER
# =============================================================================
function Resolve-Identity {
    param([string]$Identity, [string]$Type)

    $id     = $Identity.Trim()
    $isGuid = Test-IsGuid $id
    $isUPN  = Test-IsUPN  $id

    if ($Type -eq "user") {
        $obj = $null
        if ($isGuid) { try { $obj = Get-MgUser -UserId $id -ErrorAction Stop } catch {} }
        if (-not $obj -and $isUPN) { try { $obj = Get-MgUser -Filter "userPrincipalName eq '$id'" -ErrorAction Stop } catch {} }
        if (-not $obj) { try { $obj = Get-MgUser -Filter "displayName eq '$id'" -ErrorAction Stop | Select-Object -First 1 } catch {} }
        if ($obj) { return [PSCustomObject]@{ Object=$obj; ObjectType="User"; DisplayName=$obj.DisplayName; Id=$obj.Id; AppId=$null } }
        Write-Err "User not found: $id"; return $null
    }

    if ($Type -eq "sp") {
        $obj = $null
        if ($isGuid) {
            try { $obj = Get-MgServicePrincipal -ServicePrincipalId $id -ErrorAction Stop } catch {}
            if (-not $obj) { try { $obj = Get-MgServicePrincipal -Filter "appId eq '$id'" -ErrorAction Stop } catch {} }
        }
        if (-not $obj) {
            try {
                $objs = Get-MgServicePrincipal -Filter "displayName eq '$id'" -ErrorAction Stop
                if (@($objs).Count -gt 1) {
                    Write-Warn "Multiple Service Principals found with DisplayName: $id"
                    Write-Warn "Results evaluated for each match. Use ObjectId or AppId to disambiguate."
                }
                $obj = @($objs)[0]
            } catch {}
        }
        if ($obj) { return [PSCustomObject]@{ Object=$obj; ObjectType="ServicePrincipal"; DisplayName=$obj.DisplayName; Id=$obj.Id; AppId=$obj.AppId } }
        Write-Err "Service Principal not found: $id"; return $null
    }

    if ($isUPN -or $isGuid) {
        $userObj = $null
        if ($isGuid) { try { $userObj = Get-MgUser -UserId $id -ErrorAction Stop } catch {} }
        if (-not $userObj) { try { $userObj = Get-MgUser -Filter "userPrincipalName eq '$id'" -ErrorAction Stop } catch {} }
        if ($userObj) { return [PSCustomObject]@{ Object=$userObj; ObjectType="User"; DisplayName=$userObj.DisplayName; Id=$userObj.Id; AppId=$null } }
    }

    $spObj = $null
    if ($isGuid) {
        try { $spObj = Get-MgServicePrincipal -ServicePrincipalId $id -ErrorAction Stop } catch {}
        if (-not $spObj) { try { $spObj = Get-MgServicePrincipal -Filter "appId eq '$id'" -ErrorAction Stop } catch {} }
    }
    if (-not $spObj) { try { $spObj = Get-MgServicePrincipal -Filter "displayName eq '$id'" -ErrorAction Stop | Select-Object -First 1 } catch {} }
    if ($spObj) { return [PSCustomObject]@{ Object=$spObj; ObjectType="ServicePrincipal"; DisplayName=$spObj.DisplayName; Id=$spObj.Id; AppId=$spObj.AppId } }

    try { $u2 = Get-MgUser -Filter "displayName eq '$id'" -ErrorAction Stop | Select-Object -First 1; if ($u2) { return [PSCustomObject]@{ Object=$u2; ObjectType="User"; DisplayName=$u2.DisplayName; Id=$u2.Id; AppId=$null } } } catch {}

    Write-Err "Identity not found: $id"
    return $null
}

# =============================================================================
# IDENTITY ENUMERATION HELPERS
# =============================================================================
function Get-TenantSafeName {
    param([string]$DisplayName)
    $DisplayName -replace ' ','_' -replace '[\/\\:*?"<>|]',''
}

function Initialize-OutputFolder {
    param([string]$TenantSafe)
    $folder = ".\identity_enum_$TenantSafe"
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder | Out-Null
        Write-Ok "Output folder created: $folder"
    }
    return $folder
}

function Write-Section {
    param([string]$Title, [string]$Content, [string]$MainFile)
    $sep = "=" * 60
    @"

$sep
  $Title
$sep
$Content
"@ | Out-File -FilePath $MainFile -Append -Encoding UTF8
}

function ConvertTo-CacheObject {
    param([string]$ObjectType, [object]$InputObject, [string[]]$Properties)
    $hash = [ordered]@{ ObjectType = $ObjectType }
    foreach ($prop in $Properties) {
        $val = $InputObject.$prop
        if ($null -eq $val) { $hash[$prop] = ""; continue }
        if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = ($val -join ", ") }
        $val = [string]$val -replace "`r`n|`r|`n"," "
        $val = $val.Trim()
        $hash[$prop] = $val
    }
    [PSCustomObject]$hash
}

function Export-CategoryCsv {
    param([string]$FilePrefix, [string]$TenantSafe, [string]$OutputFolder, [object[]]$Data)
    $csvPath = Join-Path $OutputFolder "${FilePrefix}_${TenantSafe}.csv"
    $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    return $csvPath
}

# FIX: usa Format-List en lugar de Format-Table -AutoSize para evitar truncado de campos largos
function Export-CategoryTxt {
    param([string]$FilePrefix, [string]$TenantSafe, [string]$OutputFolder, [object[]]$Data, [string[]]$DisplayProperties)
    $txtPath = Join-Path $OutputFolder "${FilePrefix}_${TenantSafe}.txt"
    $Data | Select-Object $DisplayProperties | Format-List | Out-File -FilePath $txtPath -Encoding UTF8 -Force
    return $txtPath
}

function Save-Category {
    param(
        [string]$Label, [string]$FilePrefix, [object[]]$Data,
        [string[]]$DisplayProperties, [string]$ObjectType, [string[]]$CsvProperties,
        [string]$OutputFolder, [string]$TenantSafe, [string]$MainFile, [int]$Threshold
    )

    $count = if ($Data) { @($Data).Count } else { 0 }

    $cacheObjects = if ($count -gt 0) {
        $Data | ForEach-Object { ConvertTo-CacheObject -ObjectType $ObjectType -InputObject $_ -Properties $CsvProperties }
    } else { @() }

    $csvFile = $null
    $txtFile = $null

    if ($count -gt 0) {
        $csvFile = Export-CategoryCsv -FilePrefix $FilePrefix -TenantSafe $TenantSafe -OutputFolder $OutputFolder -Data $cacheObjects
        $txtFile = Export-CategoryTxt -FilePrefix $FilePrefix -TenantSafe $TenantSafe -OutputFolder $OutputFolder -Data $cacheObjects -DisplayProperties $DisplayProperties
    }

    $csvFileName = if ($csvFile) { Split-Path $csvFile -Leaf } else { "(no data)" }
    $txtFileName = if ($txtFile) { Split-Path $txtFile -Leaf } else { "(no data)" }

    if ($count -gt $Threshold) {
        Write-Section -Title $Label -MainFile $MainFile -Content @"
$count items found.
Full results saved to:
  $txtFileName  (human-readable)
  $csvFileName  (search cache)
"@
        return [PSCustomObject]@{ Label=$Label; Count=$count; Separate=$true; TxtFile=$txtFileName; CsvFile=$csvFileName }
    } else {
        $content = if ($count -eq 0) { "(no results)" } else { $cacheObjects | Select-Object $DisplayProperties | Format-List | Out-String }
        Write-Section -Title $Label -MainFile $MainFile -Content ($content + "`nSaved to: $txtFileName  |  $csvFileName")
        return [PSCustomObject]@{ Label=$Label; Count=$count; Separate=$false; TxtFile=$txtFileName; CsvFile=$csvFileName }
    }
}

# =============================================================================
# CORRELATION EXPORT
# =============================================================================
function Export-AllApplicationsCorrelation {
    param([string]$OutputFolder, [string]$TenantSafe)

    $token = $null
    if (Get-Variable -Name "Graph" -Scope Global -ErrorAction SilentlyContinue) { $token = $Global:Graph }

    $allApps = [System.Collections.Generic.List[object]]::new()

    if ($token) {
        Write-Host "[*] Correlation: querying Applications via REST with Graph token..." -ForegroundColor DarkCyan
        $uri = "https://graph.microsoft.com/v1.0/applications"
        do {
            try {
                $response = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop
                foreach ($app in $response.value) {
                    $allApps.Add([PSCustomObject]@{
                        DisplayName         = $app.displayName
                        AppId               = $app.appId
                        CreatedDateTime     = $app.createdDateTime
                        Id                  = $app.id
                        Notes               = $app.notes
                        KeyCredentials      = $app.keyCredentials
                        PasswordCredentials = $app.passwordCredentials
                    })
                }
                $uri = $response.'@odata.nextLink'
            } catch {
                Write-Warn "Error querying Applications: $($_.Exception.Message -split '\n' | Select-Object -First 1)"
                break
            }
        } while ($uri)
    } else {
        Write-Host "[*] Correlation: querying Applications via SDK..." -ForegroundColor DarkCyan
        if (-not (Get-MgContext)) { Write-Warn "No Graph token available for -Correlacion."; return }
        $uri = "https://graph.microsoft.com/v1.0/applications"
        do {
            try {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                foreach ($app in $response.value) {
                    $allApps.Add([PSCustomObject]@{
                        DisplayName=$app.displayName; AppId=$app.appId; CreatedDateTime=$app.createdDateTime
                        Id=$app.id; Notes=$app.notes; KeyCredentials=$app.keyCredentials; PasswordCredentials=$app.passwordCredentials
                    })
                }
                $uri = $response.'@odata.nextLink'
            } catch { Write-Warn "Error querying Applications (SDK): $($_.Exception.Message -split '\n' | Select-Object -First 1)"; break }
        } while ($uri)
    }

    if ($allApps.Count -eq 0) { Write-Warn "No Applications obtained for export."; return }

    $xmlPath = Join-Path $OutputFolder "allapps_$TenantSafe.xml"
    $allApps | Export-Clixml -Path $xmlPath -Force

    $withKeyCreds  = @($allApps | Where-Object { $_.KeyCredentials      -and @($_.KeyCredentials).Count      -gt 0 })
    $withPassCreds = @($allApps | Where-Object { $_.PasswordCredentials -and @($_.PasswordCredentials).Count -gt 0 })
    $withNotes     = @($allApps | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Notes) })
    $withAnyCreds  = @($allApps | Where-Object { ($_.KeyCredentials -and @($_.KeyCredentials).Count -gt 0) -or ($_.PasswordCredentials -and @($_.PasswordCredentials).Count -gt 0) })

    Write-Ok "Application correlation exported: $xmlPath"
    Write-Host ""
    Write-Host "  CREDENTIAL SUMMARY" -ForegroundColor Cyan
    Write-Host ("  {0,-35} {1}" -f "Total applications:",            $allApps.Count)        -ForegroundColor White
    Write-Host ("  {0,-35} {1}" -f "Apps with any credential:",      $withAnyCreds.Count)   -ForegroundColor $(if ($withAnyCreds.Count  -gt 0) { "Yellow" } else { "Gray" })
    Write-Host ("  {0,-35} {1}" -f "Apps with KeyCredentials:",      $withKeyCreds.Count)   -ForegroundColor $(if ($withKeyCreds.Count   -gt 0) { "Yellow" } else { "Gray" })
    Write-Host ("  {0,-35} {1}" -f "Apps with PasswordCredentials:", $withPassCreds.Count)  -ForegroundColor $(if ($withPassCreds.Count  -gt 0) { "Yellow" } else { "Gray" })
    Write-Host ("  {0,-35} {1}" -f "Apps with Notes:",               $withNotes.Count)      -ForegroundColor $(if ($withNotes.Count      -gt 0) { "Yellow" } else { "Gray" })

    if ($withAnyCreds.Count -gt 0) {
        Write-Host ""; Write-Host "  APPS WITH CREDENTIALS" -ForegroundColor Cyan
        foreach ($app in $withAnyCreds) {
            $keyCnt  = if ($app.KeyCredentials)      { @($app.KeyCredentials).Count      } else { 0 }
            $passCnt = if ($app.PasswordCredentials) { @($app.PasswordCredentials).Count } else { 0 }
            Write-Host ("  [+] {0,-40} KeyCreds: {1}  PasswordCreds: {2}" -f $app.DisplayName, $keyCnt, $passCnt) -ForegroundColor Green
        }
    }

    if ($withNotes.Count -gt 0) {
        Write-Host ""; Write-Host "  APPS WITH NOTES" -ForegroundColor Cyan
        foreach ($app in $withNotes) {
            $noteShort = ($app.Notes -replace "`r`n|`r|`n"," ").Trim()
            if ($noteShort.Length -gt 120) { $noteShort = $noteShort.Substring(0,117) + "..." }
            Write-Host ("  [+] {0,-40} Notes: {1}" -f $app.DisplayName, $noteShort) -ForegroundColor Green
        }
    }
    Write-Host ""
}

# =============================================================================
# MODE: ENUM
# =============================================================================
function Invoke-EnumMode {
    param([int]$Threshold)

    $mgCtx = Assert-GraphSession -Context IdentityEnum

    # FIX: usar Get-AzContext en lugar de Get-AzTenant para evitar WARNING de tenant expirado
    $azAvailable = $false
    $azCtxInfo   = $null
    try {
        $azCtx = Get-AzContext -ErrorAction Stop
        if ($azCtx) {
            $azAvailable = $true
            $azCtxInfo   = $azCtx
        }
    } catch {
        Write-Warn "Failed to query Az context. Continuing with Microsoft Graph only."
    }

    try {
        $org = $null
        for ($i = 1; $i -le 3; $i++) {
            try { $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1; if ($org) { break } }
            catch { Write-Warn "Failed to retrieve tenant information. Attempt $i/3: $($_.Exception.Message)"; Start-Sleep -Seconds (2 * $i) }
        }
        if (-not $org) { throw "Unable to retrieve tenant information after 3 attempts." }

        $tenantName = $org.DisplayName
        $tenantSafe = Get-TenantSafeName -DisplayName $tenantName
        Write-Host "[*] Tenant: $tenantName  ->  $tenantSafe" -ForegroundColor Cyan
    } catch {
        Write-Err "Failed to retrieve tenant information: $_"; exit 1
    }

    $outputFolder = Initialize-OutputFolder -TenantSafe $tenantSafe
    $mainFile     = Join-Path $outputFolder "recon_$tenantSafe.txt"

    @"
============================================================
  IDENTITY ENUMERATION -- $tenantName
  Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Graph  : $($mgCtx.Account)
============================================================
"@ | Out-File -FilePath $mainFile -Encoding UTF8

    Write-Host "[*] Enumerating: Tenant ..." -ForegroundColor DarkCyan
    try {
        $tenantContent = $org | Select-Object DisplayName, Id,
            @{N="VerifiedDomains"; E={ ($_.VerifiedDomains | ForEach-Object { $_.Name }) -join ", " }} |
            Format-List | Out-String

        # FIX: usar Get-AzContext (sin llamadas extra a otros tenants) en lugar de Get-AzTenant
        if ($azAvailable -and $azCtxInfo) {
            $azSummary = [PSCustomObject]@{
                Account          = $azCtxInfo.Account.Id
                SubscriptionName = $azCtxInfo.Subscription.Name
                SubscriptionId   = $azCtxInfo.Subscription.Id
                TenantId         = $azCtxInfo.Tenant.Id
            }
            $tenantContent += "`nAz Context:`n" + ($azSummary | Format-List | Out-String)
        } else {
            $tenantContent += "`n[!] Az Context: no active Az session."
        }
    } catch { $tenantContent = "[ERROR] $_" }
    Write-Section -Title "TENANT" -MainFile $mainFile -Content $tenantContent

    $summary = @()

    # Applications
    Write-Host "[*] Enumerating: Applications ..." -ForegroundColor DarkCyan
    try {
        $data = Get-MgApplication -All -ErrorAction Stop
        $summary += Save-Category -Label "APPLICATIONS" -FilePrefix "applications" -Data $data `
            -DisplayProperties "ObjectType","DisplayName","Id","AppId","SignInAudience","PublisherDomain","Notes" `
            -ObjectType "Application" -CsvProperties "DisplayName","Id","AppId","SignInAudience","PublisherDomain","Notes" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Applications. Missing Application.Read.All or insufficient privileges."
        Write-Section -Title "APPLICATIONS" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Applications"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Users
    Write-Host "[*] Enumerating: Users ..." -ForegroundColor DarkCyan
    try {
        $data = Get-MgUser -All -Property "DisplayName,Id,UserPrincipalName,Mail,AccountEnabled,UserType,JobTitle,Department,OfficeLocation,OnPremisesSyncEnabled,CreatedDateTime" -ErrorAction Stop
        $allUsersData = $data
        $summary += Save-Category -Label "USERS" -FilePrefix "users" -Data $data `
            -DisplayProperties "ObjectType","DisplayName","Id","UserPrincipalName","Mail","AccountEnabled","UserType","JobTitle","Department","OnPremisesSyncEnabled" `
            -ObjectType "User" -CsvProperties "DisplayName","Id","UserPrincipalName","Mail","AccountEnabled","UserType","JobTitle","Department","OfficeLocation","OnPremisesSyncEnabled","CreatedDateTime" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Users. Missing Directory.Read.All or insufficient privileges."
        Write-Section -Title "USERS" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Users"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Guests
    Write-Host "[*] Enumerating: Guests ..." -ForegroundColor DarkCyan
    try {
        $allUsers = Get-MgUser -All -Property "DisplayName,Id,UserPrincipalName,Mail,UserType,ExternalUserState,CreationType" -ErrorAction Stop
        $guestData = @($allUsers | Where-Object {
            $_.UserPrincipalName -like "*#EXT#*" -or
            $_.ExternalUserState -ne $null -or
            $_.CreationType -eq "Invitation" -or
            $_.UserType -eq "Guest"
        })
        $guestCount = $guestData.Count

        $guestCacheObjects = if ($guestCount -gt 0) {
            $guestData | ForEach-Object { ConvertTo-CacheObject -ObjectType "Guest" -InputObject $_ -Properties "DisplayName","Id","UserPrincipalName","Mail","UserType","ExternalUserState","CreationType" }
        } else { @() }

        $guestCsvFile = $null; $guestTxtFile = $null
        if ($guestCount -gt 0) {
            $guestCsvFile = Export-CategoryCsv -FilePrefix "guests" -TenantSafe $tenantSafe -OutputFolder $outputFolder -Data $guestCacheObjects
            $guestTxtPath = Join-Path $outputFolder "guests_${tenantSafe}.txt"
            $guestCacheObjects | Select-Object "ObjectType","DisplayName","Id","UserPrincipalName","Mail","UserType","ExternalUserState","CreationType" | Format-List | Out-File -FilePath $guestTxtPath -Encoding UTF8 -Force
            $guestTxtFile = $guestTxtPath
        }

        $guestCsvFileName = if ($guestCsvFile) { Split-Path $guestCsvFile -Leaf } else { "(no data)" }
        $guestTxtFileName = if ($guestTxtFile) { Split-Path $guestTxtFile -Leaf } else { "(no data)" }

        $guestContent = if ($guestCount -eq 0) { "(no results)" } else { $guestCacheObjects | Select-Object "ObjectType","DisplayName","Id","UserPrincipalName","Mail","UserType","ExternalUserState","CreationType" | Format-List | Out-String }
        Write-Section -Title "GUESTS" -MainFile $mainFile -Content ($guestContent + "`nSaved to: $guestTxtFileName  |  $guestCsvFileName")
        $summary += [PSCustomObject]@{ Label="Guests"; Count=$guestCount; Separate=$false; TxtFile=$guestTxtFileName; CsvFile=$guestCsvFileName }
    } catch {
        Write-Warn "Failed to enumerate Guests. Missing Directory.Read.All or insufficient privileges."
        Write-Section -Title "GUESTS" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Guests"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # OnPrem Synced Users
    Write-Host "[*] Enumerating: OnPrem Synced Users ..." -ForegroundColor DarkCyan
    try {
        $onpremData = @($allUsersData | Where-Object { $_.OnPremisesSyncEnabled -eq $true -or $_.OnPremisesSyncEnabled -eq "True" })
        $onpremCount = $onpremData.Count

        $onpremCacheObjects = if ($onpremCount -gt 0) {
            $onpremData | ForEach-Object { ConvertTo-CacheObject -ObjectType "User" -InputObject $_ -Properties "DisplayName","Id","UserPrincipalName","Mail","AccountEnabled","UserType","JobTitle","Department","OfficeLocation","OnPremisesSyncEnabled","CreatedDateTime" }
        } else { @() }

        $onpremCsvFile = $null; $onpremTxtFile = $null
        if ($onpremCount -gt 0) {
            $onpremCsvFile = Export-CategoryCsv -FilePrefix "onprem_users" -TenantSafe $tenantSafe -OutputFolder $outputFolder -Data $onpremCacheObjects
            $onpremTxtPath = Join-Path $outputFolder "onprem_users_${tenantSafe}.txt"
            $onpremCacheObjects | Select-Object "ObjectType","DisplayName","UserPrincipalName","Department","JobTitle","AccountEnabled","OnPremisesSyncEnabled" | Format-List | Out-File -FilePath $onpremTxtPath -Encoding UTF8 -Force
            $onpremTxtFile = $onpremTxtPath
        }

        $onpremCsvFileName = if ($onpremCsvFile) { Split-Path $onpremCsvFile -Leaf } else { "(no data)" }
        $onpremTxtFileName = if ($onpremTxtFile) { Split-Path $onpremTxtFile -Leaf } else { "(no data)" }
        $summary += [PSCustomObject]@{ Label="OnPrem Synced Users"; Count=$onpremCount; Separate=$false; TxtFile=$onpremTxtFileName; CsvFile=$onpremCsvFileName }
    } catch {
        Write-Warn "Failed to enumerate OnPrem Synced Users."
        $summary += [PSCustomObject]@{ Label="OnPrem Synced Users"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Groups
    Write-Host "[*] Enumerating: Groups ..." -ForegroundColor DarkCyan
    try {
        $data = Get-MgGroup -All -Property "DisplayName,Id,Mail,MailEnabled,SecurityEnabled,GroupTypes,Description,MembershipRule,OnPremisesSyncEnabled" -ErrorAction Stop
        $summary += Save-Category -Label "GROUPS" -FilePrefix "groups" -Data $data `
            -DisplayProperties "ObjectType","DisplayName","Id","Mail","MailEnabled","SecurityEnabled","GroupTypes","Description","MembershipRule","OnPremisesSyncEnabled" `
            -ObjectType "Group" -CsvProperties "DisplayName","Id","Mail","MailEnabled","SecurityEnabled","GroupTypes","Description","MembershipRule","OnPremisesSyncEnabled" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Groups. Missing Group.Read.All or insufficient privileges."
        Write-Section -Title "GROUPS" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Groups"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Service Principals
    Write-Host "[*] Enumerating: Service Principals ..." -ForegroundColor DarkCyan
    $allServicePrincipalsData = @()
    try {
        $data = Get-MgServicePrincipal -All -Property "DisplayName,Id,AppId,ServicePrincipalType,AccountEnabled,Tags,Notes,AppOwnerOrganizationId,CreatedDateTime,PreferredSingleSignOnMode" -ErrorAction Stop
        $allServicePrincipalsData = $data
        $summary += Save-Category -Label "SERVICE PRINCIPALS" -FilePrefix "service_principals" -Data $data `
            -DisplayProperties "ObjectType","DisplayName","Id","AppId","ServicePrincipalType","AccountEnabled","Tags" `
            -ObjectType "ServicePrincipal" -CsvProperties "DisplayName","Id","AppId","ServicePrincipalType","AccountEnabled","Tags","Notes" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Service Principals. Missing Application.Read.All or insufficient privileges."
        Write-Section -Title "SERVICE PRINCIPALS" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Service Principals"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Managed Identities
    Write-Host "[*] Enumerating: Managed Identities ..." -ForegroundColor DarkCyan
    try {
        $miData = @($allServicePrincipalsData | Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" })
        $summary += Save-Category -Label "MANAGED IDENTITIES" -FilePrefix "managed_identities" -Data $miData `
            -DisplayProperties "ObjectType","DisplayName","Id","AppId","ServicePrincipalType","AccountEnabled","Tags","AppOwnerOrganizationId","CreatedDateTime","PreferredSingleSignOnMode" `
            -ObjectType "ManagedIdentity" -CsvProperties "DisplayName","Id","AppId","ServicePrincipalType","AccountEnabled","Tags","Notes","AppOwnerOrganizationId","CreatedDateTime","PreferredSingleSignOnMode" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Managed Identities."
        Write-Section -Title "MANAGED IDENTITIES" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Managed Identities"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Directory Roles
    Write-Host "[*] Enumerating: Directory Roles ..." -ForegroundColor DarkCyan
    try {
        $data = Get-MgDirectoryRole -All -ErrorAction Stop
        $summary += Save-Category -Label "DIRECTORY ROLES" -FilePrefix "directory_roles" -Data $data `
            -DisplayProperties "ObjectType","DisplayName","Id","Description" -ObjectType "DirectoryRole" -CsvProperties "DisplayName","Id","Description" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Directory Roles. Missing Directory.Read.All or insufficient privileges."
        Write-Section -Title "DIRECTORY ROLES" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Directory Roles"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    # Administrative Units
    Write-Host "[*] Enumerating: Administrative Units ..." -ForegroundColor DarkCyan
    try {
        $data = Get-MgDirectoryAdministrativeUnit -All -ErrorAction Stop
        $summary += Save-Category -Label "ADMINISTRATIVE UNITS" -FilePrefix "administrative_units" -Data $data `
            -DisplayProperties "ObjectType","DisplayName","Id","Description" -ObjectType "AdministrativeUnit" `
            -CsvProperties "DisplayName","Id","Description" `
            -OutputFolder $outputFolder -TenantSafe $tenantSafe -MainFile $mainFile -Threshold $Threshold
    } catch {
        Write-Warn "Failed to enumerate Administrative Units. Missing Directory.Read.All or insufficient privileges."
        Write-Section -Title "ADMINISTRATIVE UNITS" -MainFile $mainFile -Content "[ERROR] $_"
        $summary += [PSCustomObject]@{ Label="Administrative Units"; Count=0; Separate=$false; TxtFile=$null; CsvFile=$null }
    }

    $countLines = $summary | ForEach-Object {
        "  {0,-25} {1,5} items  ->  {2}  |  {3}" -f $_.Label, $_.Count, $_.TxtFile, $_.CsvFile
    }
    Write-Section -Title "COUNT SUMMARY" -MainFile $mainFile -Content ($countLines -join "`n")

    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "  FINAL SUMMARY" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Ok "Tenant       : $tenantName"
    Write-Ok "Folder       : $outputFolder"
    Write-Ok "Main file    : recon_$tenantSafe.txt"
    Write-Host ""
    foreach ($item in $summary) {
        $color = if ($item.Count -gt 0) { "Green" } else { "DarkGray" }
        Write-Host ("[+] {0,-22} {1,5} items  ->  {2}  |  {3}" -f $item.Label, $item.Count, $item.TxtFile, $item.CsvFile) -ForegroundColor $color
    }
    Write-Host ""

    return [PSCustomObject]@{ TenantSafe=$tenantSafe; OutputFolder=$outputFolder }
}

# =============================================================================
# MODE: SEARCH
# =============================================================================
function Format-SearchResult {
    param([object[]]$Results)
    foreach ($r in $Results) { $r | Format-List; Write-Host ("-" * 50) -ForegroundColor DarkGray }
}

function Search-LocalCache {
    param([string]$CachePath, [string]$Query)

    $csvFiles = Get-ChildItem -Path $CachePath -Filter "*.csv" -ErrorAction SilentlyContinue
    if (-not $csvFiles) { return ,@() }

    $queryNorm = $Query -replace "`r`n|`r|`n"," "
    $queryNorm = $queryNorm.Trim().Trim('"').Trim("'").ToLower()

    $exactMatches = @(); $partialMatches = @()

    foreach ($csv in $csvFiles) {
        try { $rows = Import-Csv -Path $csv.FullName -Encoding UTF8 -ErrorAction Stop } catch { Write-Warn "Error reading $($csv.Name): $_"; continue }

        foreach ($row in $rows) {
            $matchType = $null; $matchedCol = $null; $matchedVal = $null
            foreach ($prop in $row.PSObject.Properties) {
                $rawVal = $prop.Value
                if ($null -eq $rawVal) { continue }
                $valNorm = [string]$rawVal -replace "`r`n|`r|`n"," "
                $valNorm = $valNorm.Trim().Trim('"').Trim("'").ToLower()
                if ($valNorm -eq "") { continue }
                if ($valNorm -eq $queryNorm) { $matchType = "Exact"; $matchedCol = $prop.Name; $matchedVal = $rawVal.Trim(); break }
                if ($null -eq $matchType -and $valNorm -like "*$queryNorm*") { $matchType = "Partial"; $matchedCol = $prop.Name; $matchedVal = $rawVal.Trim() }
            }
            if ($matchType) {
                $resultHash = [ordered]@{ SourceFile=$csv.Name; MatchType=$matchType; MatchedColumn=$matchedCol; MatchedValue=$matchedVal }
                foreach ($prop in $row.PSObject.Properties) { $resultHash[$prop.Name] = ($prop.Value -replace "`r`n|`r|`n"," ").Trim() }
                $obj = [PSCustomObject]$resultHash
                if ($matchType -eq "Exact") { $exactMatches += $obj } else { $partialMatches += $obj }
            }
        }
    }
    return ,@($exactMatches + $partialMatches)
}

function ConvertTo-ShortIdentityObject {
    param([object]$GraphObject)
    $odata = $GraphObject.AdditionalProperties.'@odata.type'
    if (-not $odata) {
        if     ($GraphObject.PSObject.Properties.Name -contains "UserPrincipalName")                                                                 { $odata = "#microsoft.graph.user" }
        elseif ($GraphObject.PSObject.Properties.Name -contains "AppId" -and $GraphObject.PSObject.Properties.Name -contains "ServicePrincipalType") { $odata = "#microsoft.graph.servicePrincipal" }
        elseif ($GraphObject.PSObject.Properties.Name -contains "AppId")                                                                            { $odata = "#microsoft.graph.application" }
        elseif ($GraphObject.PSObject.Properties.Name -contains "MailEnabled")                                                                      { $odata = "#microsoft.graph.group" }
        elseif ($GraphObject.PSObject.Properties.Name -contains "Description" -and -not ($GraphObject.PSObject.Properties.Name -contains "AppId"))  { $odata = "#microsoft.graph.administrativeUnit" }
        else   { $odata = "#microsoft.graph.directoryRole" }
    }
    switch ($odata) {
        "#microsoft.graph.user"               { return [PSCustomObject]@{ ObjectType="User";              DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id; UserPrincipalName=$GraphObject.UserPrincipalName; Mail=$GraphObject.Mail; AccountEnabled=$GraphObject.AccountEnabled; UserType=$GraphObject.UserType; JobTitle=$GraphObject.JobTitle; Department=$GraphObject.Department } }
        "#microsoft.graph.group"              { return [PSCustomObject]@{ ObjectType="Group";             DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id; Mail=$GraphObject.Mail; MailEnabled=$GraphObject.MailEnabled; SecurityEnabled=$GraphObject.SecurityEnabled; GroupTypes=($GraphObject.GroupTypes -join ", "); Description=$GraphObject.Description; MembershipRule=$GraphObject.MembershipRule } }
        "#microsoft.graph.servicePrincipal"   { return [PSCustomObject]@{ ObjectType="ServicePrincipal"; DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id; AppId=$GraphObject.AppId; ServicePrincipalType=$GraphObject.ServicePrincipalType; AccountEnabled=$GraphObject.AccountEnabled; Tags=($GraphObject.Tags -join ", ") } }
        "#microsoft.graph.application"        { return [PSCustomObject]@{ ObjectType="Application";      DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id; AppId=$GraphObject.AppId; SignInAudience=$GraphObject.SignInAudience; PublisherDomain=$GraphObject.PublisherDomain; Notes=$GraphObject.Notes } }
        "#microsoft.graph.directoryRole"      { return [PSCustomObject]@{ ObjectType="DirectoryRole";    DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id; Description=$GraphObject.Description } }
        "#microsoft.graph.administrativeUnit" { return [PSCustomObject]@{ ObjectType="AdministrativeUnit"; DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id; Description=$GraphObject.Description } }
        default                               { return [PSCustomObject]@{ ObjectType="Unknown";           DisplayName=$GraphObject.DisplayName; Id=$GraphObject.Id } }
    }
}

function Search-LiveGraph {
    param([string]$Query, [bool]$Deep)
    $found  = @()
    $isGuid = Test-IsGuid -Value $Query
    if ($Deep) { Write-Warn "Deep mode enabled. This may be slow in large tenants." }

    if ($isGuid) {
        $resolvers = @(
            { Get-MgUser -UserId $Query -ErrorAction Stop },
            { Get-MgGroup -GroupId $Query -ErrorAction Stop },
            { Get-MgServicePrincipal -ServicePrincipalId $Query -ErrorAction Stop },
            { Get-MgApplication -ApplicationId $Query -ErrorAction Stop },
            { Get-MgDirectoryRole -DirectoryRoleId $Query -ErrorAction Stop },
            { Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $Query -ErrorAction Stop }
        )
        foreach ($r in $resolvers) { try { $obj = & $r; if ($obj) { $found += ConvertTo-ShortIdentityObject $obj } } catch {} }
    } else {
        $filters = @(
            { Get-MgUser -Filter "userPrincipalName eq '$Query'" -ErrorAction Stop },
            { Get-MgUser -Filter "displayName eq '$Query'" -ErrorAction Stop },
            { Get-MgGroup -Filter "displayName eq '$Query'" -ErrorAction Stop },
            { Get-MgServicePrincipal -Filter "displayName eq '$Query'" -ErrorAction Stop },
            { Get-MgApplication -Filter "displayName eq '$Query'" -ErrorAction Stop },
            { Get-MgDirectoryRole -Filter "displayName eq '$Query'" -ErrorAction Stop },
            { Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$Query'" -ErrorAction Stop }
        )
        foreach ($f in $filters) { try { $objs = & $f; if ($objs) { $objs | ForEach-Object { $found += ConvertTo-ShortIdentityObject $_ } } } catch {} }

        if ($Deep) {
            $deepSearches = @(
                { Get-MgUser -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$Query*" -or $_.UserPrincipalName -like "*$Query*" } },
                { Get-MgServicePrincipal -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$Query*" } },
                { Get-MgApplication -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$Query*" } },
                { Get-MgGroup -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$Query*" } }
            )
            foreach ($s in $deepSearches) { try { $objs = & $s; if ($objs) { $objs | ForEach-Object { $found += ConvertTo-ShortIdentityObject $_ } } } catch {} }
        }
    }

    $unique = @{}; $deduped = @()
    foreach ($obj in $found) { if ($obj.Id -and -not $unique.ContainsKey($obj.Id)) { $unique[$obj.Id] = $true; $deduped += $obj } }
    return $deduped
}

function Invoke-SearchMode {
    param([string]$Query, [string]$CachePath, [bool]$Live, [bool]$Deep)

    if (-not $Query) { Write-Err "-Query is required for -Mode search."; exit 1 }

    if (-not $CachePath) {
        try {
            $candidates = Get-ChildItem -Path "." -Directory -Filter "identity_enum_*" -ErrorAction SilentlyContinue
            if ($candidates) { $CachePath = ($candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName; Write-Info "Cache auto-detected: $CachePath" }
            else { Write-Warn "No cache folder found. Run: .\recon.ps1 -Mode enum"; if (-not $Live) { exit 1 } }
        } catch { Write-Warn "Failed to auto-detect cache folder." }
    }

    Write-Ok "Searching local cache..."
    $cacheResults = @()
    if ($CachePath -and (Test-Path $CachePath)) {
        try { $cacheResults = Search-LocalCache -CachePath $CachePath -Query $Query } catch { Write-Warn "Error searching local cache: $_" }
    }

    if ($cacheResults.Count -gt 0) {
        if ($cacheResults.Count -gt 1) {
            $uniqueNames = $cacheResults | Select-Object -ExpandProperty DisplayName -Unique
            Write-Host ""; Write-Warn "Multiple objects found matching: $Query"
            if ($uniqueNames.Count -lt $cacheResults.Count) { Write-Warn "DisplayName is not unique. Use Id or AppId to disambiguate." }
        }
        Write-Host ""; Format-SearchResult -Results $cacheResults; return
    }

    Write-Err "No object found in local cache."

    if ($Live) {
        Write-Info "Querying Microsoft Graph live..."
        Assert-GraphSession -Context SearchLive | Out-Null
        try {
            $liveResults = Search-LiveGraph -Query $Query -Deep $Deep
            if ($liveResults.Count -gt 0) {
                if ($liveResults.Count -gt 1) { Write-Host ""; Write-Warn "Multiple objects found matching: $Query"; Write-Warn "Use Id or AppId to disambiguate." }
                Write-Host ""; Format-SearchResult -Results $liveResults
            } else { Write-Err "No object found in Graph (live)." }
        } catch { Write-Warn "Failed to query Graph live: $_" }
    } else {
        Write-Host "    Use -Live to query Microsoft Graph." -ForegroundColor DarkGray
    }
}

# =============================================================================
# POLICY: AUTHENTICATION METHODS
# =============================================================================
function Write-CompactLine { param([string]$Line = "") Write-Host $Line; $script:OutputBuffer.Add($Line) }

function Write-CompactBlock {
    param([System.Collections.IDictionary]$Data)
    foreach ($k in $Data.Keys) { Write-CompactLine ("{0,-28} : {1}" -f $k, $Data[$k]) }
}

function Resolve-AuthMethodTargets {
    param([object[]]$Targets)
    if (-not $Targets -or $Targets.Count -eq 0) { return "All" }
    $resolved = foreach ($t in $Targets) {
        if ($t.id -eq "all_users" -or $t.id -eq "All") { "All"; continue }
        if ($t.targetType -eq "group") { try { $g = Get-MgGroup -GroupId $t.id -ErrorAction Stop; "[GROUP] $($g.DisplayName)" } catch { "[GROUP] $($t.id)" } }
        else { $t.id }
    }
    return ($resolved -join ", ")
}

function Expand-AuthMethodTargetMembers {
    param([object[]]$Targets)
    if (-not $Targets -or $Targets.Count -eq 0) { Write-Host "`nTargets" -ForegroundColor White; Write-Ok "Applies to: All users"; return }
    Write-Host "`nTargets" -ForegroundColor White
    foreach ($t in $Targets) {
        if ($t.id -eq "all_users" -or $t.id -eq "All") { Write-Ok "Applies to: All users"; continue }
        if ($t.targetType -eq "group") {
            $groupName = $t.id
            try { $grp = Get-MgGroup -GroupId $t.id -ErrorAction Stop; $groupName = $grp.DisplayName } catch {}
            $members = $null
            try {
                $memberObjs = Get-MgGroupMember -GroupId $t.id -All -ErrorAction Stop
                $members = ($memberObjs | ForEach-Object { $ap = $_.AdditionalProperties; if ($ap.userPrincipalName) { $ap.userPrincipalName } elseif ($ap.displayName) { $ap.displayName } else { $_.Id } }) -join ", "
            } catch { $members = "Unable to enumerate members - insufficient permissions"; Write-Warn "Failed to resolve group members." }
            Write-Obj ([PSCustomObject]@{ TargetType=$t.targetType; TargetId=$t.id; TargetName=$groupName; IsRegistrationRequired=$t.isRegistrationRequired; Members=$members })
        } else { Write-Obj ([PSCustomObject]@{ TargetType=$t.targetType; TargetId=$t.id }) }
    }
}

function Get-EnabledAuthenticationMethods {
    Write-Sep "ENABLED CONDITIONAL ACCESS POLICIES"
    try {
        $caps = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop | Where-Object { $_.State -eq "enabled" }
        if (-not $caps) { Write-Ok "No enabled Conditional Access Policies found." } else {
            $first = $true
            foreach ($cap in $caps) {
                if (-not $first) { Write-CompactLine "" }; $first = $false
                $grantType = ""; $grantControls = ""; $authStrength = ""; $allowedCombs = ""; $operator = ""
                if ($cap.GrantControls) {
                    $operator  = $cap.GrantControls.Operator
                    $builtIn   = @($cap.GrantControls.BuiltInControls) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    $strengthObj   = $cap.GrantControls.AuthenticationStrength
                    $strengthName  = if ($strengthObj) { [string]$strengthObj.DisplayName } else { "" }
                    $strengthCombs = if ($strengthObj) { @($strengthObj.AllowedCombinations) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } } else { @() }
                    $hasRealStrength = (-not [string]::IsNullOrWhiteSpace($strengthName)) -or ($strengthCombs.Count -gt 0)
                    if ($builtIn.Count -gt 0) { $grantType = "BuiltInControls"; $grantControls = ($builtIn -join ", ") }
                    elseif ($hasRealStrength) { $grantType = "AuthenticationStrength"; $authStrength = $strengthName; $allowedCombs = ($strengthCombs -join ", ") }
                    else { $grantType = "NoControls" }
                }
                $inclUsersStr  = if ($cap.Conditions.Users.IncludeUsers  -and $cap.Conditions.Users.IncludeUsers.Count  -gt 0) { Resolve-Collection $cap.Conditions.Users.IncludeUsers  $true } else { "(none)" }
                $exclUsersStr  = if ($cap.Conditions.Users.ExcludeUsers  -and $cap.Conditions.Users.ExcludeUsers.Count  -gt 0) { Resolve-Collection $cap.Conditions.Users.ExcludeUsers  $true } else { "(none)" }
                $inclGroupsStr = if ($cap.Conditions.Users.IncludeGroups -and $cap.Conditions.Users.IncludeGroups.Count -gt 0) { Resolve-Collection $cap.Conditions.Users.IncludeGroups $true } else { "(none)" }
                $exclGroupsStr = if ($cap.Conditions.Users.ExcludeGroups -and $cap.Conditions.Users.ExcludeGroups.Count -gt 0) { Resolve-Collection $cap.Conditions.Users.ExcludeGroups $true } else { "(none)" }
                $block = [ordered]@{ DisplayName=$cap.DisplayName; State=$cap.State; GrantType=$grantType }
                if ($grantType -eq "BuiltInControls") { $block["GrantControls"] = $grantControls; $block["Operator"] = $operator }
                elseif ($grantType -eq "AuthenticationStrength") { $block["AuthStrength"] = $authStrength; $block["AllowedCombs"] = $allowedCombs }
                $block["IncludeUsers"] = $inclUsersStr; $block["ExcludeUsers"] = $exclUsersStr
                $block["IncludeGroups"] = $inclGroupsStr; $block["ExcludeGroups"] = $exclGroupsStr
                Write-CompactBlock $block
            }
        }
    } catch { Write-Warn "Failed to enumerate Conditional Access Policies: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }

    Write-Sep "ENABLED AUTHENTICATION METHODS"
    try {
        $policy  = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        $methods = $policy.AuthenticationMethodConfigurations | Where-Object { $_.State -eq "enabled" }
        if (-not $methods) { Write-Ok "No enabled authentication methods found."; return }
        $first = $true
        foreach ($m in $methods) {
            if (-not $first) { Write-CompactLine "" }; $first = $false
            $targets = $m.AdditionalProperties.includeTargets
            $scope   = Resolve-AuthMethodTargets -Targets $targets
            $block   = [ordered]@{ AuthenticationMethod=$m.Id; State=$m.State; TargetScope=$scope }
            switch ($m.Id) {
                "TemporaryAccessPass"    { $ap = $m.AdditionalProperties; $block["IsUsableOnce"] = $ap.isUsableOnce; $block["DefaultLifetime"] = "$($ap.defaultLifetimeInMinutes) min"; $block["Hint"] = "-> Full detail: -AuthMeth -AuthType TAP" }
                "X509Certificate"        { $block["Hint"] = "-> Full detail: -AuthMeth -AuthType X509" }
                "Fido2"                  { $block["Hint"] = "-> Full detail: -AuthMeth -AuthType FIDO2" }
                "MicrosoftAuthenticator" { $block["Hint"] = "-> Full detail: -AuthMeth -AuthType MicrosoftAuthenticator" }
                "Email"                  { $block["Hint"] = "-> Full detail: -AuthMeth -AuthType Email" }
                "Sms"                    { $block["Hint"] = "-> Full detail: -AuthMeth -AuthType SMS" }
            }
            Write-CompactBlock $block
        }
    } catch { Write-Warn "Failed to enumerate Authentication Method Policies: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-TAPConfiguration {
    Write-Sep "TEMPORARY ACCESS PASS (TAP)"
    try {
        $TAPConfig = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId TemporaryAccessPass -ErrorAction Stop
        $TAP = $TAPConfig.AdditionalProperties
        Write-Host "`nTemporary Access Pass configuration" -ForegroundColor White
        Write-Obj ([PSCustomObject]@{ DefaultLifetime=$TAP.defaultLifetimeInMinutes; MinimumLifetime=$TAP.minimumLifetimeInMinutes; MaximumLifetime=$TAP.maximumLifetimeInMinutes; DefaultLength=$TAP.defaultLength; IsUsableOnce=$TAP.isUsableOnce })
        Write-Host "`nTAP Targets" -ForegroundColor White
        $targets = $TAP.includeTargets
        if (-not $targets) { Write-Ok "No targets configured."; return }
        Expand-AuthMethodTargetMembers -Targets $targets
    } catch { Write-Warn "Failed to read TAP configuration: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-X509Configuration {
    Write-Sep "X509 CERTIFICATE AUTHENTICATION"
    try {
        $cfg = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId X509Certificate -ErrorAction Stop
        $ap  = $cfg.AdditionalProperties
        Write-Host "`nX509Certificate configuration" -ForegroundColor White
        Write-CompactLine ("{0,-28} : {1}" -f "State", $cfg.State)
        Expand-AuthMethodTargetMembers -Targets $ap.includeTargets
        $authMode = $ap.authenticationModeConfiguration
        if ($authMode) {
            Write-Host "`nAuthentication Mode" -ForegroundColor White
            Write-CompactLine ("{0,-28} : {1}" -f "DefaultMode", $authMode.x509CertificateAuthenticationDefaultMode)
            $ruleList = $authMode.rules
            if ($ruleList -and @($ruleList).Count -gt 0) { Write-Host "`nAuthentication Mode Rules" -ForegroundColor White; foreach ($rule in $ruleList) { Write-CompactLine ("  RuleType: {0,-30} Identifier: {1,-40} AuthMode: {2}" -f $rule.x509CertificateRuleType, $rule.identifier, $rule.x509CertificateAuthenticationMode) } }
        }
        $bindings = $ap.certificateUserBindings
        if ($bindings -and @($bindings).Count -gt 0) { Write-Host "`nCertificate User Bindings" -ForegroundColor White; foreach ($b in $bindings) { Write-CompactLine ("  Priority: {0}  UserProperty: {1,-25} CertificateField: {2}" -f $b.priority, $b.userProperty, $b.x509CertificateField) } }
        else { Write-Ok "No certificate user bindings configured." }
    } catch { Write-Warn "Failed to read X509Certificate configuration: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-FIDO2Configuration {
    Write-Sep "FIDO2 SECURITY KEYS"
    try {
        $cfg = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId Fido2 -ErrorAction Stop
        $ap  = $cfg.AdditionalProperties
        Write-Host "`nFIDO2 configuration" -ForegroundColor White
        Write-CompactLine ("{0,-28} : {1}" -f "State",                   $cfg.State)
        Write-CompactLine ("{0,-28} : {1}" -f "IsAttestationEnforced",   $ap.isAttestationEnforced)
        Write-CompactLine ("{0,-28} : {1}" -f "SelfServiceRegistration", $ap.isSelfServiceRegistrationAllowed)
        Expand-AuthMethodTargetMembers -Targets $ap.includeTargets
        $kr = $ap.keyRestrictions
        if ($kr) {
            Write-Host "`nKey Restrictions" -ForegroundColor White
            Write-CompactLine ("{0,-28} : {1}" -f "IsEnforced",      $kr.isEnforced)
            Write-CompactLine ("{0,-28} : {1}" -f "EnforcementType", $kr.enforcementType)
            $guids = if ($kr.aaGuids -and @($kr.aaGuids).Count -gt 0) { ($kr.aaGuids -join ", ") } else { "(none)" }
            Write-CompactLine ("{0,-28} : {1}" -f "AaGuids", $guids)
        } else { Write-Ok "No key restrictions configured." }
    } catch { Write-Warn "Failed to read FIDO2 configuration: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-MicrosoftAuthenticatorConfiguration {
    Write-Sep "MICROSOFT AUTHENTICATOR"
    try {
        $cfg = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId MicrosoftAuthenticator -ErrorAction Stop
        $ap  = $cfg.AdditionalProperties
        Write-Host "`nMicrosoft Authenticator configuration" -ForegroundColor White
        Write-CompactLine ("{0,-28} : {1}" -f "State",                 $cfg.State)
        Write-CompactLine ("{0,-28} : {1}" -f "IsSoftwareOathEnabled", $ap.isSoftwareOathEnabled)
        Expand-AuthMethodTargetMembers -Targets $ap.includeTargets
        $features = $ap.featureSettings
        if ($features) {
            Write-Host "`nFeature Settings" -ForegroundColor White
            $nm = $features.numberMatchingRequiredState
            $ac = $features.displayAppInformationRequiredState
            $lc = $features.displayLocationInformationRequiredState
            $nmStr = if ($nm) { "$($nm.state) (target: $($nm.includeTarget.targetType) $($nm.includeTarget.id))" } else { "(not configured)" }
            $acStr = if ($ac) { "$($ac.state) (target: $($ac.includeTarget.targetType) $($ac.includeTarget.id))" } else { "(not configured)" }
            $lcStr = if ($lc) { "$($lc.state) (target: $($lc.includeTarget.targetType) $($lc.includeTarget.id))" } else { "(not configured)" }
            Write-CompactLine ("{0,-28} : {1}" -f "NumberMatching",    $nmStr)
            Write-CompactLine ("{0,-28} : {1}" -f "AdditionalContext", $acStr)
            Write-CompactLine ("{0,-28} : {1}" -f "LocationContext",   $lcStr)
            if ($nm -and $nm.state -ne "enabled") { Write-Warn "NumberMatching is NOT enabled. MFA fatigue attacks may be possible." }
            elseif ($nm -and $nm.state -eq "enabled") { Write-Ok "NumberMatching is enabled. MFA fatigue attacks are mitigated." }
        } else { Write-Warn "No feature settings found. NumberMatching status unknown." }
    } catch { Write-Warn "Failed to read Microsoft Authenticator configuration: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-EmailOTPConfiguration {
    Write-Sep "EMAIL ONE-TIME PASSCODE (OTP)"
    try {
        $cfg = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId Email -ErrorAction Stop
        $ap  = $cfg.AdditionalProperties
        Write-Host "`nEmail OTP configuration" -ForegroundColor White
        Write-Obj ([PSCustomObject]@{ State=$cfg.State; AllowExternalIdToUseEmailOtp=$ap.allowExternalIdToUseEmailOtp })
        Expand-AuthMethodTargetMembers -Targets $ap.includeTargets
        if ($cfg.State -eq "enabled") { Write-Warn "Email OTP is enabled. This is the weakest MFA method -- phishable via email compromise." }
    } catch { Write-Warn "Failed to read Email OTP configuration: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-SMSConfiguration {
    Write-Sep "SMS AUTHENTICATION"
    try {
        $cfg = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId Sms -ErrorAction Stop
        $ap  = $cfg.AdditionalProperties
        Write-Host "`nSMS configuration" -ForegroundColor White
        Write-Obj ([PSCustomObject]@{ State=$cfg.State })
        Expand-AuthMethodTargetMembers -Targets $ap.includeTargets
        if ($cfg.State -eq "enabled") { Write-Warn "SMS authentication is enabled. Vulnerable to SIM swapping attacks." }
    } catch { Write-Warn "Failed to read SMS configuration: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-CrossTenantAccessPolicies {
    param([bool]$Detailed)
    Write-Sep "CROSS-TENANT ACCESS POLICIES"
    try {
        $partners = Get-MgPolicyCrossTenantAccessPolicyPartner -ErrorAction Stop
        if (-not $partners) { Write-Ok "No Cross-Tenant Access Policy Partners found."; return }
        foreach ($p in $partners) {
            $obj = [ordered]@{
                TenantId                = $p.TenantId
                OutboundAllowed         = $p.AutomaticUserConsentSettings.OutboundAllowed
                InboundAllowed          = $p.AutomaticUserConsentSettings.InboundAllowed
                MfaAccepted             = $p.InboundTrust.IsMfaAccepted
                CompliantDeviceAccepted = $p.InboundTrust.IsCompliantDeviceAccepted
                HybridJoinedAccepted    = $p.InboundTrust.IsHybridAzureAdJoinedDeviceAccepted
                MultiTenantOrg          = $p.AdditionalProperties.isInMultiTenantOrganization
            }
            if ($Detailed) {
                $obj["B2BCollabOutbound"]        = $p.B2BCollaborationOutbound.UsersAndGroups.AccessType
                $obj["B2BCollabInbound"]         = $p.B2BCollaborationInbound.UsersAndGroups.AccessType
                $obj["B2BDirectConnectOutbound"] = $p.B2BDirectConnectOutbound.UsersAndGroups.AccessType
                $obj["B2BDirectConnectInbound"]  = $p.B2BDirectConnectInbound.UsersAndGroups.AccessType
            }
            Write-Obj ([PSCustomObject]$obj)
        }
    } catch { Write-Warn "Failed to enumerate Cross-Tenant Access Policies: $($_.Exception.Message -split '\n' | Select-Object -First 1)" }
}

function Get-ConditionalAccessPoliciesForUser {
    param([object]$ResolvedIdentity, [bool]$Detailed, [bool]$Raw, [bool]$DoResolve)
    $user = $ResolvedIdentity.Object
    Write-Sep "CONDITIONAL ACCESS -- USER"
    Write-Info "TargetIdentity : $($user.UserPrincipalName)"
    Write-Info "TargetObjectId : $($user.Id)"
    Write-Info "TargetType     : User"
    Write-Host ""

    $userGroupIds = @()
    try { $userGroupIds = Get-MgUserTransitiveMemberOf -UserId $user.Id -All -ErrorAction Stop | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } | Select-Object -ExpandProperty Id }
    catch { Write-Warn "Failed to resolve group transitive membership." }

    $policies = @()
    try { $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop }
    catch { Write-Warn "Failed to enumerate Conditional Access Policies: $($_.Exception.Message -split '\n' | Select-Object -First 1)"; return }

    $results = foreach ($policy in $policies) {
        $directMatch = $policy.Conditions.Users.IncludeUsers  -contains $user.Id
        $allUsers    = $policy.Conditions.Users.IncludeUsers  -contains "All"
        $groupMatch  = @($policy.Conditions.Users.IncludeGroups | Where-Object { $userGroupIds -contains $_ }).Count -gt 0
        $exclDirect  = $policy.Conditions.Users.ExcludeUsers  -contains $user.Id
        $exclGroup   = @($policy.Conditions.Users.ExcludeGroups | Where-Object { $userGroupIds -contains $_ }).Count -gt 0
        $included    = $directMatch -or $allUsers -or $groupMatch
        $excluded    = $exclDirect -or $exclGroup
        $applies     = $included -and (-not $excluded)
        $effectiveState = if ($applies) { switch ($policy.State) { "enabled" { "enabled_applicable" } "enabledForReportingButNotEnforced" { "reportOnly_applicable" } "disabled" { "disabled" } default { "unknown" } } } elseif ($excluded) { "excluded" } else { "not_applicable" }
        if ($effectiveState -notin @("enabled_applicable","reportOnly_applicable","excluded")) { continue }

        $row = [ordered]@{ PolicyName=$policy.DisplayName; State=$policy.State; EffectiveState=$effectiveState; AppliesToIdentity=$applies; IncludedByUser=$directMatch; IncludedByAllUsers=$allUsers; IncludedByGroup=$groupMatch; ExcludedUser=$exclDirect; ExcludedByGroup=$exclGroup; GrantControls=($policy.GrantControls.BuiltInControls -join ", "); GrantOperator=$policy.GrantControls.Operator; AuthenticationStrength=$policy.GrantControls.AuthenticationStrength.DisplayName; ClientAppTypes=($policy.Conditions.ClientAppTypes -join ", "); IncludeApplications=Resolve-Collection $policy.Conditions.Applications.IncludeApplications $DoResolve; ExcludeApplications=Resolve-Collection $policy.Conditions.Applications.ExcludeApplications $DoResolve }
        if ($Detailed) {
            $row["IncludeUsers"] = Resolve-Collection $policy.Conditions.Users.IncludeUsers $DoResolve; $row["ExcludeUsers"] = Resolve-Collection $policy.Conditions.Users.ExcludeUsers $DoResolve
            $row["IncludeGroups"] = Resolve-Collection $policy.Conditions.Users.IncludeGroups $DoResolve; $row["ExcludeGroups"] = Resolve-Collection $policy.Conditions.Users.ExcludeGroups $DoResolve
            $row["IncludePlatforms"] = ($policy.Conditions.Platforms.IncludePlatforms -join ", "); $row["ExcludePlatforms"] = ($policy.Conditions.Platforms.ExcludePlatforms -join ", ")
            $row["IncludeLocations"] = Resolve-Collection $policy.Conditions.Locations.IncludeLocations $DoResolve; $row["ExcludeLocations"] = Resolve-Collection $policy.Conditions.Locations.ExcludeLocations $DoResolve
            $row["SignInFrequency"] = $policy.SessionControls.SignInFrequency.Value; $row["PersistentBrowser"] = $policy.SessionControls.PersistentBrowser.Mode
            $row["DeviceFilterMode"] = $policy.Conditions.Devices.DeviceFilter.Mode; $row["DeviceFilterRule"] = $policy.Conditions.Devices.DeviceFilter.Rule
            $row["SignInRiskLevels"] = ($policy.Conditions.SignInRiskLevels -join ", "); $row["UserRiskLevels"] = ($policy.Conditions.UserRiskLevels -join ", ")
        }
        if ($Raw) { Write-Host ($policy | Format-List | Out-String); continue }
        [PSCustomObject]$row
    }

    if (-not $Raw) { $results | ForEach-Object { $f = [ordered]@{}; $_.PSObject.Properties | ForEach-Object { if (-not [string]::IsNullOrWhiteSpace([string]$_.Value)) { $f[$_.Name] = $_.Value } }; Write-Obj ([PSCustomObject]$f) } }
    if (-not $results) { Write-Ok "No Conditional Access Policies apply to this user (enabled or report-only)." }
}

function Get-ConditionalAccessPoliciesForServicePrincipal {
    param([object]$ResolvedIdentity, [bool]$Detailed, [bool]$Raw, [bool]$DoResolve)
    $sp = $ResolvedIdentity.Object
    Write-Sep "CONDITIONAL ACCESS -- SERVICE PRINCIPAL"
    Write-Info "TargetIdentity : $($sp.DisplayName)"
    Write-Info "TargetObjectId : $($sp.Id)"
    Write-Info "TargetAppId    : $($sp.AppId)"
    Write-Info "TargetType     : ServicePrincipal"
    Write-Host ""

    $policies = @()
    try { $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop }
    catch { Write-Warn "Failed to enumerate Conditional Access Policies: $($_.Exception.Message -split '\n' | Select-Object -First 1)"; return }

    $results = foreach ($policy in $policies) {
        $directSP = $policy.Conditions.ServicePrincipals.IncludeServicePrincipals -contains $sp.Id
        $allSPs   = $policy.Conditions.ServicePrincipals.IncludeServicePrincipals -contains "All"
        $exclSP   = $policy.Conditions.ServicePrincipals.ExcludeServicePrincipals -contains $sp.Id
        $applies  = ($directSP -or $allSPs) -and (-not $exclSP)
        $effectiveState = if ($applies) { switch ($policy.State) { "enabled" { "enabled_applicable" } "enabledForReportingButNotEnforced" { "reportOnly_applicable" } "disabled" { "disabled" } default { "unknown" } } } elseif ($exclSP) { "excluded" } else { "not_applicable" }
        if ($effectiveState -notin @("enabled_applicable","reportOnly_applicable","excluded")) { continue }

        $row = [ordered]@{ PolicyName=$policy.DisplayName; State=$policy.State; EffectiveState=$effectiveState; AppliesToSP=$applies; IncludedBySP=$directSP; IncludedByAllSPs=$allSPs; ExcludedSP=$exclSP; GrantControls=($policy.GrantControls.BuiltInControls -join ", "); GrantOperator=$policy.GrantControls.Operator; AuthenticationStrength=$policy.GrantControls.AuthenticationStrength.DisplayName; ClientAppTypes=($policy.Conditions.ClientAppTypes -join ", "); IncludeServicePrincipals=Resolve-Collection $policy.Conditions.ServicePrincipals.IncludeServicePrincipals $DoResolve; ExcludeServicePrincipals=Resolve-Collection $policy.Conditions.ServicePrincipals.ExcludeServicePrincipals $DoResolve; IncludeApplications=Resolve-Collection $policy.Conditions.Applications.IncludeApplications $DoResolve; ExcludeApplications=Resolve-Collection $policy.Conditions.Applications.ExcludeApplications $DoResolve }
        if ($Detailed) {
            $row["IncludePlatforms"] = ($policy.Conditions.Platforms.IncludePlatforms -join ", "); $row["ExcludePlatforms"] = ($policy.Conditions.Platforms.ExcludePlatforms -join ", ")
            $row["IncludeLocations"] = Resolve-Collection $policy.Conditions.Locations.IncludeLocations $DoResolve; $row["ExcludeLocations"] = Resolve-Collection $policy.Conditions.Locations.ExcludeLocations $DoResolve
            $row["SignInFrequency"] = $policy.SessionControls.SignInFrequency.Value; $row["PersistentBrowser"] = $policy.SessionControls.PersistentBrowser.Mode
            $row["DeviceFilterMode"] = $policy.Conditions.Devices.DeviceFilter.Mode; $row["DeviceFilterRule"] = $policy.Conditions.Devices.DeviceFilter.Rule
        }
        if ($Raw) { Write-Host ($policy | Format-List | Out-String); continue }
        [PSCustomObject]$row
    }

    if (-not $Raw) { $results | ForEach-Object { $f = [ordered]@{}; $_.PSObject.Properties | ForEach-Object { if (-not [string]::IsNullOrWhiteSpace([string]$_.Value)) { $f[$_.Name] = $_.Value } }; Write-Obj ([PSCustomObject]$f) } }
    if (-not $results) { Write-Ok "No Conditional Access Policies apply to this Service Principal (enabled or report-only)." }
}

# =============================================================================
# ENTRY POINT
# =============================================================================
$anyAction = $Mode -or $Correlacion -or $AuthMeth -or $Tenant -or $CAP -or $AuthType

if ($Help -or -not $anyAction) { Show-Help; exit 0 }

if ($Mode -eq "enum") {
    try { $enumResult = Invoke-EnumMode -Threshold $Threshold } catch { Write-Err "Fatal error during enumeration: $_"; exit 1 }
    if ($Correlacion) { try { Export-AllApplicationsCorrelation -OutputFolder $enumResult.OutputFolder -TenantSafe $enumResult.TenantSafe } catch { Write-Warn "Failed to export correlation: $_" } }
    return
}

if ($Mode -eq "search") {
    try { Invoke-SearchMode -Query $Query -CachePath $CachePath -Live $Live.IsPresent -Deep $Deep.IsPresent } catch { Write-Warn "Error during search: $_" }
    return
}

if ($Correlacion) {
    try {
        $ctx = Assert-GraphSession -Context Correlation
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $tenantSafe = Get-TenantSafeName -DisplayName $org.DisplayName
        $outFolder  = ".\identity_enum_$tenantSafe"
        if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder | Out-Null; Write-Ok "Output folder created: $outFolder" } else { Write-Info "Using existing output folder: $outFolder" }
        Export-AllApplicationsCorrelation -OutputFolder $outFolder -TenantSafe $tenantSafe
    } catch { Write-Warn "Failed to export correlation: $_" }
    return
}

if ($AuthMeth -or $AuthType -or $Tenant -or $CAP) {
    Assert-GraphSession -Context Policy | Out-Null

    if ($AuthMeth -and -not $AuthType) { Get-EnabledAuthenticationMethods }

    if ($AuthType) {
        switch ($AuthType.ToUpper()) {
            "TAP"                    { Get-TAPConfiguration }
            "X509"                   { Get-X509Configuration }
            "FIDO2"                  { Get-FIDO2Configuration }
            "MICROSOFTAUTHENTICATOR" { Get-MicrosoftAuthenticatorConfiguration }
            "EMAIL"                  { Get-EmailOTPConfiguration }
            "SMS"                    { Get-SMSConfiguration }
            default                  { Write-Err "Unknown -AuthType '$AuthType'. Valid: TAP, X509, FIDO2, MicrosoftAuthenticator, Email, SMS" }
        }
    }

    if ($Tenant) { try { Get-CrossTenantAccessPolicies -Detailed $Detailed.IsPresent } catch { Write-Warn "Error enumerating Cross-Tenant Access Policies: $_" } }

    if ($CAP) {
        if (-not $Identity) { Write-Err "-Identity is required for -CAP."; exit 1 }
        try {
            $resolved = Resolve-Identity -Identity $Identity.Trim() -Type $Type
            if (-not $resolved) { exit 1 }
            if ($resolved.ObjectType -eq "User") { Get-ConditionalAccessPoliciesForUser -ResolvedIdentity $resolved -Detailed $Detailed.IsPresent -Raw $Raw.IsPresent -DoResolve $ResolveIds.IsPresent }
            elseif ($resolved.ObjectType -eq "ServicePrincipal") { Get-ConditionalAccessPoliciesForServicePrincipal -ResolvedIdentity $resolved -Detailed $Detailed.IsPresent -Raw $Raw.IsPresent -DoResolve $ResolveIds.IsPresent }
        } catch { Write-Warn "Failed to evaluate Conditional Access Policies: $_" }
    }
}

if ($OutputPath -and $script:OutputBuffer.Count -gt 0) {
    try { $script:OutputBuffer | Out-File -FilePath $OutputPath -Encoding UTF8 -Force; Write-Ok "Output saved to: $OutputPath" }
    catch { Write-Err "Failed to save output to $OutputPath : $($_.Exception.Message)" }
}
``` 


