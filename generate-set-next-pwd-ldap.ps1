# Utilize the Get-Credential cmdlet to prompt for Windows authentication
$cred = Get-Credential -Message "Enter your CyberArk credentials"

# Define variables for the API endpoint
$baseUrl = "https://pvwa1.mylab.net/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/ldap/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"
$GeneratePassword = "$baseUrl/Accounts/22_14/Secret/Generate/"
$SetNextPassword = "$baseUrl/Accounts/22_14/SetNextPassword/"

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

# Perform POST request to generate password 
try {
    $response = Invoke-RestMethod -Uri $GeneratePassword -Method 'POST' -Headers $headers
    $newPassword = $response.Password
    Write-Host "Successfully generated new password: $newPassword"
} catch {
    Write-Host "Failed to generate new password. Response: $($_.Exception.Response.StatusCode) - $($_.Exception.Response.StatusDescription)"
    Write-Host "Detailed Error: $($_.Exception.Message)"
    exit
}

# Prepare the body for setting the next password using the newly generated password
$body = @{
    ChangeImmediately = $true
    NewCredentials = $newPassword
} | ConvertTo-Json

# Perform POST request to set next password 
try {
    $response = Invoke-RestMethod -Uri $SetNextPassword -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json
    Write-Host "Successfully set the new password as the next password."
} catch {
    Write-Host "Failed to set the new password as the next password. Response: $($_.Exception.Response.StatusCode) - $($_.Exception.Response.StatusDescription)"
    Write-Host "Detailed Error: $($_.Exception.Message)"
    exit
}

# Logoff from session
try {
    $response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
    Write-Host "Success...logging off"
} catch {
    Write-Host "Failed to log off."
    exit
}
