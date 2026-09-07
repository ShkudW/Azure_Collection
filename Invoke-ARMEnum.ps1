Function Invoke-ARMEnum {
    param (
        [string]$AccessToken,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$Identity,
        [string]$TenantName
    )

#######################################################################################################
#######################################################################################################
    $global:AuthMethod = $null
    $global:CID  = $null
    $global:CSecret = $null
    $global:TenantID = $null
    $global:AccessToken = $null

#######################################################################################################
#######################################################################################################

function Get-AuthHeaders {
    if (-not $global:AccessToken) {
        throw "[-] No AccessToken available. Run Invoke-GetTokens first."
    }
    return @{
        "Authorization" = "Bearer $($global:AccessToken)"
        "Content-Type" = "application/json"
        "UserAgent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }
}

#######################################################################################################
#######################################################################################################


function Invoke-RenewToken {
    Write-Host "`t[!] Token expired - renewing ($($global:AuthMethod))..." -ForegroundColor Yellow

    switch ($global:AuthMethod) {
        "ClientCredentials" {
            if (-not $global:CID -or -not $global:CSecret -or -not $global:TenantID) {
                throw "[-] Missing ClientID/ClientSecret/TenantID for token renewal."
            }
            $url = "https://login.microsoftonline.com/$($global:TenantID)/oauth2/v2.0/token"
            $body = @{
                "client_id" = $global:CID
                "client_secret" = $global:CSecret
                "scope"  = "https://management.azure.com/.default"
                "grant_type" = "client_credentials"
            }
            try {
                $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
                $global:AccessToken = $resp.access_token
                Write-Host "`t[+] Token renewed (ClientCredentials)" -ForegroundColor Green
                return $global:AccessToken
            }
            catch { throw "[-] Failed to renew token with ClientCredentials: $_" }
        }
        "RefreshToken" {
            $refreshPath = "C:\Users\Public\RefreshToken.txt"
            if (-not (Test-Path $refreshPath)) {
                throw "[-] No RefreshToken file found at $refreshPath"
            }
            $RefreshToken = Get-Content $refreshPath
            $url = "https://login.microsoftonline.com/$($global:TenantID)/oauth2/v2.0/token"
            $body = @{
                "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "scope" = "https://management.azure.com/.default"
                "grant_type" = "refresh_token"
                "refresh_token" = $RefreshToken
            }
            try {
                $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
                if ($resp.refresh_token) {
                    Set-Content -Path $refreshPath -Value $resp.refresh_token
                    Write-Host "`t[>] New RefreshToken saved" -ForegroundColor DarkGray
                }
                $global:AccessToken = $resp.access_token
                Write-Host "`t[+] Token renewed (RefreshToken)" -ForegroundColor Green
                return $global:AccessToken
            }
            catch { throw "[-] Failed to renew token with RefreshToken: $_" }
        }
        "Manual" {
            Write-Host "`n`t[!] Cannot auto-renew token for Managed Identity." -ForegroundColor Yellow
            Write-Host "`t[?] Please paste a new AccessToken below:" -ForegroundColor Cyan
            $newToken = Read-Host "`tAccessToken"
            if ([string]::IsNullOrWhiteSpace($newToken)) {
                throw "[-] No token provided. Cannot continue."
            }
            $global:AccessToken = $newToken.Trim()
            Write-Host "`t[+] Token updated (Manual)" -ForegroundColor Green
            return $global:AccessToken
        }
        default { throw "[-] Unknown AuthMethod '$($global:AuthMethod)'." }
    }
}


#######################################################################################################

function Invoke-SmartRequest {
    param (
        [string]$Method = $null,
        [string]$Uri,
        [hashtable]$Headers = $null,
        $Body = $null,
        [string]$ContentType = $null,
        [int]$MaxRetries = 15
    )

    if (-not $Headers) {
         $Headers = Get-AuthHeaders
    }

    $RetryCount = 0
    $TokenRenewed = $false
    $Success = $false
    $Response = $null

    while (-not $Success -and $RetryCount -lt $MaxRetries) {
        try {
            $p = @{ Method = $Method; Uri = $Uri; Headers = $Headers }
            if ($null -ne $Body)  { $p['Body'] = $Body }
            if ($ContentType)     { $p['ContentType'] = $ContentType }

            $Response = Invoke-RestMethod @p
            $Success  = $true
        }
        catch {
            $err  = $_
            $code = if ($err.Exception.Response) { [int]$err.Exception.Response.StatusCode } else { $null }

            if ($code -eq 429) {
                $RetryCount++
                $ra   = $err.Exception.Response.Headers["Retry-After"]
                $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) { [int]($ra -join '') } else { 0 }
                if ($wait -eq 0) { $wait = 10 * $RetryCount }
                Write-Host "`t[!] 429 Rate Limit - waiting $wait sec ($RetryCount/$MaxRetries)" -ForegroundColor Gray
                Start-Sleep -Seconds $wait
            }
            elseif ($code -eq 401) {
                if ($TokenRenewed) { throw "[-] 401 after token renewal." }
                try {
                    Invoke-RenewToken | Out-Null
                    $Headers["Authorization"] = "Bearer $($global:AccessToken)"
                    $TokenRenewed = $true
                    Write-Host "`t[>] Retrying with new token..." -ForegroundColor Cyan
                }
                catch { throw "[-] Token renewal failed: $_" }
            }
            elseif ($code -eq 403) { throw "[-] 403 Forbidden - $Uri" }
            elseif ($code -eq 404) { return $null }
            elseif ($null -eq $code -or $code -ge 500) {
                $RetryCount++
                $wait = 5 * $RetryCount
                Write-Host "`t[!] Error ($code). Retrying in $wait sec ($RetryCount/$MaxRetries)" -ForegroundColor Yellow
                Start-Sleep -Seconds $wait
            }
            else { throw $err }
        }
    }
    if (-not $Success) { throw "[-] Request to $Uri failed after $MaxRetries retries." }
    return $Response
}


#######################################################################################################

function Get-DomainName {
    param ([string]$DomainName)
    try {
        $response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
        $TenantID = ($response.issuer -split "/")[3]
        Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
        return $TenantID
    } catch {
        Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
        return $null
    }
}

#######################################################################################################

function Invoke-GetTokens {
    param(
        [string]$DomainName,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$AccessToken
    )

    if ($AccessToken) {
        $global:AuthMethod  = "Manual"
        $global:AccessToken = $AccessToken
        Write-Host "[+] Token set (Manual)" -ForegroundColor Green
        return $global:AccessToken
    }

    if ($DomainName) {
        $global:TenantID = Get-DomainName -DomainName $DomainName
        if (-not $global:TenantID) { return $null }
    }

    if ($ClientID -and $ClientSecret) {
        $global:AuthMethod = "ClientCredentials"
        $global:CID = $ClientID
        $global:CSecret = $ClientSecret

        $url = "https://login.microsoftonline.com/$($global:TenantID)/oauth2/v2.0/token"
        $body = @{
            "client_id" = $ClientID
            "client_secret" = $ClientSecret
            "scope" = "https://management.azure.com/.default"
            "grant_type" = "client_credentials"
        }
        try {
            $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
            $global:AccessToken = $resp.access_token
            Write-Host "[+] Token acquired (ClientCredentials)" -ForegroundColor Green
            return $global:AccessToken
        }
        catch {
            Write-Error "[-] Failed to get token: $_"
            return $null
        }
    }

    # Device Code Flow - check for existing RefreshToken first
    $global:AuthMethod = "RefreshToken"
    $refreshPath = "C:\Users\Public\RefreshToken.txt"

    if (Test-Path $refreshPath) {
        Write-Host "[?] Found existing RefreshToken at $refreshPath" -ForegroundColor DarkYellow
        $useExisting = Read-Host "    Use existing RefreshToken? (Y/N)"

        if ($useExisting -match "^[Yy]") {
            $RefreshToken = Get-Content $refreshPath
            $url = "https://login.microsoftonline.com/$($global:TenantID)/oauth2/v2.0/token"
            $body = @{
                "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "scope"         = "https://management.azure.com/.default"
                "grant_type"    = "refresh_token"
                "refresh_token" = $RefreshToken
            }
            try {
                $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
                if ($resp.refresh_token) {
                    Set-Content -Path $refreshPath -Value $resp.refresh_token
                }
                $global:AccessToken = $resp.access_token
                Write-Host "[+] Token acquired (RefreshToken)" -ForegroundColor Green
                return $global:AccessToken
            }
            catch {
                Write-Host "[!] RefreshToken expired or invalid. Falling back to Device Code..." -ForegroundColor Yellow
            }
        }
    }

    # Device Code Flow
    $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
    $Body = @{
        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "resource"  = "https://management.azure.com"
    }

    $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $Body
    $code       = $authResponse.user_code
    $deviceCode = $authResponse.device_code

    Write-Host "`n[#] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkYellow -NoNewline
    Write-Host " $code" -ForegroundColor White
    Start-Sleep -Seconds 5
    Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

    $tokenUrl  = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"
    $tokenBody = @{
        "scope"      = "openid"
        "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
        "code"       = $deviceCode
    }

    while ($true) {
        try {
            $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            if ($tokenResponse.refresh_token) {
                Set-Content -Path $refreshPath -Value $tokenResponse.refresh_token
                Write-Host "[>] Refresh Token saved" -ForegroundColor DarkGray
            }
            $global:AccessToken = $tokenResponse.access_token
            Write-Host "[+] Token acquired (DeviceCode)" -ForegroundColor Green
            return $global:AccessToken
        }
        catch {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($errorResponse.error -eq "authorization_pending") { Start-Sleep -Seconds 5 }
            elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                Write-Host "`n[-] Authorization failed or expired." -ForegroundColor DarkRed
                return $null
            }
            else {
                Write-Host "`n[-] Unexpected error: $($errorResponse.error)" -ForegroundColor DarkRed
                return $null
            }
        }
    }
}

#######################################################################################################
#######################################################################################################

function Test-OpAllowed {
    param(
        [string[]]$Allowed,
        [string[]]$Denied,
        [string]$Operation
    )
    $match = $false
    foreach ($pat in $Allowed) {
        if ($Operation -like $pat) { $match = $true; break }
    }
    if (-not $match) { return $false }
    foreach ($pat in $Denied) {
        if ($Operation -like $pat) { return $false }
    }
    return $true
}

function Get-ResourcePermissions {
    param(
        [string]$ResourceId,
        [hashtable]$Headers
    )

    $url = "https://management.azure.com$ResourceId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    try {
        $resp = Invoke-SmartRequest -Uri $url -Headers $Headers -Method GET
    }
    catch {
        return $null
    }

    if (-not $resp -or -not $resp.value) {
         return $null 
    }

    $allow = @()
    $deny = @()
    $allowData = @()
    $denyData = @()

    foreach ($p in $resp.value) {
        if ($p.actions) { 
            $allow += $p.actions 
        }
        if ($p.notActions) {
             $deny += $p.notActions 
        }
        if ($p.dataActions)  { 
            $allowData += $p.dataActions 
        }
        if ($p.notDataActions) {
             $denyData  += $p.notDataActions 
        }
    }

    return @{
        Allow = ($allow | Select-Object -Unique)
        Deny = ($deny  | Select-Object -Unique)
        AllowData = ($allowData | Select-Object -Unique)
        DenyData  = ($denyData  | Select-Object -Unique)
    }
}

#######################################################################################################
#######################################################################################################

function Get-PermissionSummary {
    param(
        [hashtable]$Perms,
        [string]$ResourceType
    )

    $a  = if ($Perms.Allow) { 
        $Perms.Allow 
    } 
    else {
         @() 
    }

    $d  = if ($Perms.Deny) {
         $Perms.Deny 
    } 
    else {
         @() 
    }

    $da = if ($Perms.AllowData) {
         $Perms.AllowData 
    }  
    else {
         @() 
    }

    $dd = if ($Perms.DenyData)  {
         $Perms.DenyData 
    } 
    else {
         @()
    }

    $hasStar = Test-OpAllowed -Allowed $a -Denied $d -Operation '*'
    $canManageRBAC = Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Authorization/roleAssignments/write'
    $globalRead = Test-OpAllowed -Allowed $a -Denied $d -Operation '*/read'
    $denyAll = ($d -contains '*')


    $role = if ($denyAll) { "Denied (*)" }
            elseif ($canManageRBAC -and $hasStar) { "Owner" }
            elseif ($hasStar) { "Contributor" }
            elseif ($globalRead) { "Reader" }
            else { "Custom/Limited" }

  
    $capabilities = @()

    switch ($ResourceType) {

        "KeyVault" {
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/secrets/read') {
                 $capabilities += "ARM:SecretsRead" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/secrets/write') {
                 $capabilities += "ARM:SecretsWrite" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/keys/read') {
                 $capabilities += "ARM:KeysRead" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/certificates/read') {
                 $capabilities += "ARM:CertsRead" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/accessPolicies/write')  {
                 $capabilities += "ARM:AccessPolicyWrite" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/write')  {
                 $capabilities += "ARM:VaultWrite"
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.KeyVault/vaults/delete') {
                 $capabilities += "ARM:VaultDelete" 
            }

            # Data plane
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.KeyVault/vaults/secrets/getSecret/action')  {
                 $capabilities += "DATA:GetSecret"
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.KeyVault/vaults/secrets/setSecret/action'){
                 $capabilities += "DATA:SetSecret" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.KeyVault/vaults/keys/sign/action') {
                 $capabilities += "DATA:KeySign" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.KeyVault/vaults/keys/decrypt/action')  {
                 $capabilities += "DATA:KeyDecrypt" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.KeyVault/vaults/certificates/import/action')  {
                 $capabilities += "DATA:CertImport" 
            }
        }


        "StorageAccount" {
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.Storage/storageAccounts/listKeys/action') {
                 $capabilities += "ARM:ListKeys" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.Storage/storageAccounts/write') {
                 $capabilities += "ARM:AccountWrite" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.Storage/storageAccounts/delete') {
                 $capabilities += "ARM:AccountDelete" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.Storage/storageAccounts/regenerateKey/action') {
                 $capabilities += "ARM:RegenKey" 
            }
            if (Test-OpAllowed -Allowed $a  -Denied $d  -Operation 'Microsoft.Storage/storageAccounts/listAccountSas/action') {
                 $capabilities += "ARM:ListSAS" 
            }

            # Data plane
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read') {
                 $capabilities += "DATA:BlobRead" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write') {
                 $capabilities += "DATA:BlobWrite" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete') {
                 $capabilities += "DATA:BlobDelete" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read') {
                 $capabilities += "DATA:FileRead" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Storage/storageAccounts/tableServices/tables/entities/read') {
                 $capabilities += "DATA:TableRead" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Storage/storageAccounts/queueServices/queues/messages/read') {
                 $capabilities += "DATA:QueueRead" 
            }
        }


        "WebApp" {
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/publish/action') {
                 $capabilities += "Publish" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/config/list/action') {
                 $capabilities += "ListConfig" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/config/write') {
                 $capabilities += "ConfigWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/write') {
                 $capabilities += "SiteWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/restart/action') {
                 $capabilities += "Restart" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/functions/action')  {
                 $capabilities += "Functions" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/extensions/write')  {
                 $capabilities += "ExtensionsWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/publishxml/action') {
                 $capabilities += "PublishXML" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/basicPublishingCredentialsPolicies/write') {
                 $capabilities += "BasicAuthPolicy" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/config/snapshots/read') {
                 $capabilities += "SnapshotRead" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Web/sites/sourcecontrols/write')  {
                 $capabilities += "SourceControl" 
            }
        }


        "VirtualMachine" {
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/extensions/write') {
                 $capabilities += "ExtensionWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/runCommand/action') {
                 $capabilities += "RunCommand" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/write') {
                 $capabilities += "VMWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/start/action') {
                 $capabilities += "Start" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/restart/action')  {
                 $capabilities += "Restart" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/deallocate/action') {
                 $capabilities += "Deallocate" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/virtualMachines/delete') {
                 $capabilities += "Delete" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/disks/read')  {
                 $capabilities += "DiskRead" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/disks/write') {
                 $capabilities += "DiskWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Compute/disks/beginGetAccess/action') {
                 $capabilities += "DiskSAS" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Network/networkInterfaces/read') {
                 $capabilities += "NicRead" 
            }
            
            # Data plane
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Compute/virtualMachines/login/action') {
                 $capabilities += "DATA:Login" 
            }
            if (Test-OpAllowed -Allowed $da -Denied $dd -Operation 'Microsoft.Compute/virtualMachines/loginAsAdmin/action') { 
                $capabilities += "DATA:AdminLogin" 
            }
        }


        "SQL" {
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/read') {
                 $capabilities += "ServerRead" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/write'){
                 $capabilities += "ServerWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/databases/read')  {
                 $capabilities += "DBRead" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/databases/write') {
                 $capabilities += "DBWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/firewallRules/write')  {
                 $capabilities += "FirewallWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/firewallRules/delete') {
                 $capabilities += "FirewallDelete" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/administrators/write') {
                 $capabilities += "AdminWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/databases/export/action') {
                 $capabilities += "DBExport" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/databases/import/action') {
                 $capabilities += "DBImport" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/auditingSettings/write')  {
                 $capabilities += "AuditWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/connectionPolicies/write')  {
                 $capabilities += "ConnPolicyWrite" 
            }
            if (Test-OpAllowed -Allowed $a -Denied $d -Operation 'Microsoft.Sql/servers/databases/transparentDataEncryption/write') {
                 $capabilities += "TDEWrite" 
            }
        }
    }

    return @{
        Role = $role
        Capabilities = $capabilities
        AllowRaw = $a
        DenyRaw = $d
        AllowDataRaw = $da
        DenyDataRaw = $dd
    }
}

#######################################################################################################
#######################################################################################################

$script:ResourceTypeMap = @{
    "Microsoft.KeyVault/vaults" = "KeyVault"
    "Microsoft.Storage/storageAccounts" = "StorageAccount"
    "Microsoft.Web/sites" = "WebApp"
    "Microsoft.Compute/virtualMachines"  = "VirtualMachine"
    "Microsoft.Sql/servers" = "SQL"
}

function Get-Subscriptions {
    param([hashtable]$Headers)

    Write-Host "`n[*] Enumerating Subscriptions..." -ForegroundColor Cyan
    $resp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions?api-version=2021-01-01" -Headers $Headers -Method GET

    if (-not $resp -or -not $resp.value) {
        Write-Host "[!] No subscriptions found." -ForegroundColor Red
        return @()
    }

    $subs = $resp.value | ForEach-Object {
        [PSCustomObject]@{
            SubscriptionId  = $_.subscriptionId
            SubscriptionName = $_.displayName
            State = $_.state
        }
    }

    Write-Host "[+] Found $($subs.Count) subscription(s)" -ForegroundColor Green
    foreach ($s in $subs) {
        Write-Host "    - $($s.SubscriptionName) ($($s.SubscriptionId)) [$($s.State)]" -ForegroundColor Gray
    }
    return $subs
}

function Get-ResourcesByType {
    param(
        [string]$SubscriptionId,
        [string]$ResourceType,
        [hashtable]$Headers
    )

    $uri  = "https://management.azure.com/subscriptions/$SubscriptionId/resources?`$filter=resourceType eq '$ResourceType'&api-version=2021-04-01"
    $resp = Invoke-SmartRequest -Uri $uri -Headers $Headers -Method GET

    if (-not $resp -or -not $resp.value) { return @() }
    return $resp.value
}

#######################################################################################################
#######################################################################################################

function Show-ResourcePermissions {
    param(
        [string]$ResourceType,
        [array]$Results
    )

    if ($Results.Count -eq 0) { return }

    $typeLabel = $ResourceType.ToUpper()
    $line = "-" * 100

    Write-Host "`n$line" -ForegroundColor DarkCyan
    Write-Host "  $typeLabel ($($Results.Count) resources)" -ForegroundColor White
    Write-Host "$line" -ForegroundColor DarkCyan

    foreach ($r in $Results) {
        $roleColor = switch ($r.Role) {
            "Owner"{ "Red" }
            "Contributor"{ "Yellow" }
            "Reader"{ "DarkGray" }
            "Denied (*)"{ "DarkRed" }
            default { "White" }
        }

        Write-Host "  [$($r.Subscription)]" -ForegroundColor DarkGray -NoNewline
        Write-Host " $($r.Name)" -ForegroundColor Cyan -NoNewline
        Write-Host " | RG: $($r.ResourceGroup)" -ForegroundColor DarkGray -NoNewline
        Write-Host " | Role: " -NoNewline -ForegroundColor Gray
        Write-Host "$($r.Role)" -ForegroundColor $roleColor

        if ($r.Capabilities.Count -gt 0) {
            # Split into ARM and DATA capabilities
            $armCaps  = $r.Capabilities | Where-Object { $_ -notmatch "^DATA:" }
            $dataCaps = $r.Capabilities | Where-Object { $_ -match "^DATA:" } | ForEach-Object { $_ -replace "^DATA:", "" }

            if ($armCaps.Count -gt 0) {
                Write-Host "      ARM:  " -NoNewline -ForegroundColor DarkYellow
                Write-Host ($armCaps -join ", ") -ForegroundColor Yellow
            }
            if ($dataCaps.Count -gt 0) {
                Write-Host "      DATA: " -NoNewline -ForegroundColor DarkMagenta
                Write-Host ($dataCaps -join ", ") -ForegroundColor Magenta
            }
        }
        else {
            if ($r.Role -ne "Denied (*)" -and $r.Role -ne "Reader") {
                Write-Host "      (no specific high-value ops detected)" -ForegroundColor DarkGray
            }
        }
    }
}

#######################################################################################################
#######################################################################################################

function Export-Results {
    param(
        [hashtable]$AllResults,
        [string]$TenantName
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename  = "ARMMapper_${TenantName}_${timestamp}.csv"
    $outPath   = Join-Path ([Environment]::GetFolderPath("Desktop")) $filename

    $rows = @()
    foreach ($type in $AllResults.Keys) {
        foreach ($r in $AllResults[$type]) {
            $rows += [PSCustomObject]@{
                ResourceType = $type
                Name  = $r.Name
                ResourceGroup = $r.ResourceGroup
                Subscription  = $r.Subscription
                Role  = $r.Role
                Capabilities  = ($r.Capabilities -join "; ")
                ResourceId  = $r.ResourceId
            }
        }
    }

    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[+] Results exported to: $outPath" -ForegroundColor Green
    }
}

#######################################################################################################
#######################################################################################################

function main {
    param (
        [string]$AccessToken,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$Identity,
        [string]$TenantName
    )

    if (-not $TenantName) {
        Write-Host "[-] Must specify TenantName" -ForegroundColor Red
        return
    }

    $global:TenantID = Get-DomainName -DomainName $TenantName
    if (-not $global:TenantID) {
        Write-Host "[-] Could not resolve TenantID." -ForegroundColor Red
        return
    }

    if ($Identity) {
        Invoke-GetTokens -AccessToken $Identity | Out-Null
    }
    elseif ($ClientID -and $ClientSecret) {
        Invoke-GetTokens -DomainName $TenantName -ClientID $ClientID -ClientSecret $ClientSecret | Out-Null
    }
    else {
        Invoke-GetTokens -DomainName $TenantName | Out-Null
    }

    if (-not $global:AccessToken) {
        Write-Host "[-] Failed to acquire token." -ForegroundColor Red
        return
    }

    $headers = Get-AuthHeaders

    # Enumerate Subscriptions
    $subscriptions = Get-Subscriptions -Headers $headers
    if ($subscriptions.Count -eq 0) { return }

    # Scan Resources 
    $allResults = @{}

    foreach ($typeFull in $script:ResourceTypeMap.Keys) {
        $typeShort = $script:ResourceTypeMap[$typeFull]
        $typeResults = @()

        Write-Host "`n[*] Scanning $typeShort resources..." -ForegroundColor Cyan

        foreach ($sub in $subscriptions) {
            if ($sub.State -ne "Enabled") { continue }

            $resources = Get-ResourcesByType -SubscriptionId $sub.SubscriptionId -ResourceType $typeFull -Headers $headers

            foreach ($res in $resources) {
                $rgMatch = $res.id -match "/resourceGroups/([^/]+)/"
                $rg = if ($rgMatch) { $Matches[1] } else { "Unknown" }

                Write-Host "    [>] $($res.name)" -ForegroundColor DarkGray -NoNewline

                $perms = Get-ResourcePermissions -ResourceId $res.id -Headers $headers

                if ($perms) {
                    $summary = Get-PermissionSummary -Perms $perms -ResourceType $typeShort

                    Write-Host " --> $($summary.Role)" -ForegroundColor $(
                        switch ($summary.Role) {
                            "Owner"  {
                                 "Red" 
                            }
                            "Contributor" {
                                 "Yellow" 
                            }
                            "Reader" {
                                 "DarkGray" 
                            }
                            default {
                                 "White" 
                            }
                        }
                    )

                    $typeResults += [PSCustomObject]@{
                        Name  = $res.name
                        ResourceGroup = $rg
                        Subscription = $sub.SubscriptionName
                        ResourceId = $res.id
                        Role  = $summary.Role
                        Capabilities  = $summary.Capabilities
                    }
                }
                else {
                    Write-Host " --> No Access" -ForegroundColor DarkRed
                    $typeResults += [PSCustomObject]@{
                        Name = $res.name
                        ResourceGroup = $rg
                        Subscription = $sub.SubscriptionName
                        ResourceId = $res.id
                        Role = "No Access"
                        Capabilities  = @()
                    }
                }
            }
        }

        $allResults[$typeShort] = $typeResults
    }

    $totalResources = 0
    $highPriv = 0

    foreach ($type in $allResults.Keys) {
        Show-ResourcePermissions -ResourceType $type -Results $allResults[$type]
        $totalResources += $allResults[$type].Count
        $highPriv += ($allResults[$type] | Where-Object { $_.Role -match "Owner|Contributor" }).Count
    }

    # Summary
    Write-Host "`n-------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  Total Resources: $totalResources" -ForegroundColor White
    Write-Host "  High Privilege:  $highPriv" -ForegroundColor $(if ($highPriv -gt 0) { "Red" } else { "Green" })
    Write-Host "-------------------------------------------------" -ForegroundColor DarkCyan

    # -- Export ------------------------------------------------------
    $export = Read-Host "`n[?] Export results to CSV? (Y/N)"
    if ($export -match "^[Yy]") {
        Export-Results -AllResults $allResults -TenantName $TenantName
    }

    Write-Host "[] Done" -ForegroundColor Cyan
}

main -TenantName $TenantName -ClientID $ClientID -ClientSecret $ClientSecret -Identity $Identity -AccessToken $AccessToken

}
