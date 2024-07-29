# Utilize the Get-Credential cmdlet to prompt for Windows authentication
$cred = Get-Credential -Message "Enter your CyberArk credentials"

# Prompt the user to input the safe name
$safeName = Read-Host -Prompt "Enter the Safe Name"

# Define variables for the API endpoint
$baseUrl = "https://pvwa1.mylab.net/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/LDAP/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"
$getAccounts = "$baseUrl/Accounts?filter=safename eq $safeName"

# Extract the username and encrypted password from the credential object
$username = $cred.UserName
$password = $cred.GetNetworkCredential().Password

# Create the body for the authentication request
$authBody = @{
    username = $username
    password = $password
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

# Perform GET request to retrieve accounts 
$response = Invoke-RestMethod -Uri $getAccounts -Method 'GET' -Headers $headers
$response | ConvertTo-Json

# Logoff from session
$response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
Write-Host "Success...logging off"
