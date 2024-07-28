# Prompt the user for CyberArk PAS credentials
$username = Read-Host "Enter your CyberArk username"
$password = Read-Host "Enter your CyberArk password" -AsSecureString

# Convert the secure string password to plain text
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Prompt the user for the safe name and the Active Directory user group
$safeName = Read-Host "Enter the safe name to be added"
$adUserGroup = Read-Host "Enter the AD user group to be added as a safe member"

# Define variables for the API endpoint
$baseUrl = "https://pvwa1.mylab.net/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/ldap/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"
$addSafeEndpoint = "$baseUrl/safes"
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
    exit
}

# Create the headers for the GET requests using the session token
$headers = @{
    "Authorization" = $sessionToken
    "Content-Type" = "application/json"
}

# Parameters for the new safe
$body = @"
{
    `"SafeName`": `"$safeName`",
    `"Description`": `"This safe was provisioned via REST API`",
    `"OLACEnabled`": false,
    `"ManagingCPM`": `"PasswordManager`",
    `"NumberOfVersionsRetention`": null,
    `"NumberOfDaysRetention`": 7,
    `"AutoPurgeEnabled`": false,
    `"Location`": `""`
}
"@

# Perform Add Safe operation
$response = Invoke-RestMethod -Uri $addSafeEndpoint -Method 'POST' -Headers $headers -Body $body
$response | ConvertTo-Json

# Set safe permissions for safe members
$body = @"
{
    `"memberName`": `"$adUserGroup`",
    `"searchIn`": `"mylab.net`",
    `"membershipExpirationDate`": 123456,
    `"permissions`": {
        `"useAccounts`": true,
        `"retrieveAccounts`": true,
        `"listAccounts`": true,
        `"addAccounts`": true,
        `"updateAccountContent`": true,
        `"updateAccountProperties`": true,
        `"initiateCPMAccountManagementOperations`": true,
        `"specifyNextAccountContent`": true,
        `"renameAccounts`": true,
        `"deleteAccounts`": true,
        `"unlockAccounts`": true,
        `"manageSafe`": true,
        `"manageSafeMembers`": false,
        `"backupSafe`": false,
        `"viewAuditLog`": true,
        `"viewSafeMembers`": true,
        `"accessWithoutConfirmation`": true,
        `"createFolders`": false,
        `"deleteFolders`": false,
        `"moveAccountsAndFolders`": false,
        `"requestsAuthorizationLevel1`": false,
        `"requestsAuthorizationLevel2`": false
    }
}
"@

# Perform Add Safe Members operation
$response = Invoke-RestMethod -Uri $addSafeMembers -Method 'POST' -Headers $headers -Body $body
$response | ConvertTo-Json

# Logoff from session
$response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
Write-Host "Success...logging off"
