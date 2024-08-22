# Prompt the user for CyberArk PAS credentials
$username = Read-Host "Enter your CyberArk username"
$password = Read-Host "Enter your CyberArk password" -AsSecureString

# Convert the secure string password to plain text
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Prompt the user for the safe name and the Active Directory user group
$safeName = Read-Host "Enter the safe name"
$adUserGroup = Read-Host "Enter the AD user group for safe membership"

# Define variables for the API endpoint
$baseUrl = "https://pvwa1.mylab.net/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/ldap/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"
$addSafeMembers = "$baseUrl/safes/$safeName/members"

# Create the body for the authentication request
$authBody = @{
    username = $username
    password = $plainPassword
} | ConvertTo-Json

# Authenticate to the CyberArk REST API to get a session token
try {
    $authResponse = Invoke-RestMethod -Uri $authEndpoint -Method 'POST' -Body $authBody -ContentType 'application/json'
    $sessionToken = $authResponse
    Write-Host "Successfully authenticated."
} catch {
    Write-Host "Failed to authenticate. Please check your credentials and try again."
    Write-Host "Error details: $($_.Exception.Message)"
    exit
}

# Create the headers for the GET requests using the session token
$headers = @{
    "Authorization" = $sessionToken
    "Content-Type" = "application/json"
}

# Parameters for Add Safe Members
$body = @"
{
    `"memberName`": `"$adUserGroup`",
    `"searchIn`": `"mylab.net`",
    `"membershipExpirationDate`": 123456,
    `"permissions`": {
        `"useAccounts`": false,
        `"retrieveAccounts`": false,
        `"listAccounts`": true,
        `"addAccounts`": false,
        `"updateAccountContent`": false,
        `"updateAccountProperties`": false,
        `"initiateCPMAccountManagementOperations`": false,
        `"specifyNextAccountContent`": false,
        `"renameAccounts`": false,
        `"deleteAccounts`": false,
        `"unlockAccounts`": false,
        `"manageSafe`": true,
        `"manageSafeMembers`": false,
        `"backupSafe`": false,
        `"viewAuditLog`": true,
        `"viewSafeMembers`": true,
        `"accessWithoutConfirmation`": false,
        `"createFolders`": false,
        `"deleteFolders`": false,
        `"moveAccountsAndFolders`": false,
        `"requestsAuthorizationLevel1`": false,
        `"requestsAuthorizationLevel2`": false
    }
}
"@

# Perform Add Safe Members operation
try {
    $response = Invoke-RestMethod -Uri $addSafeMembers -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json
    Write-Host "Successfully added user group to the safe."
} catch {
    Write-Host "Failed to add user group to the safe. Please check your inputs and try again."
    Write-Host "Error details: $($_.Exception.Message)"
}

# Logoff from session
$response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
Write-Host "Success...logging off"
