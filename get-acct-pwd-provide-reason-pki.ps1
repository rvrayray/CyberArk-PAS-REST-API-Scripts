# Utilize the Get-Credential cmdlet to prompt for Windows authentication
$cred = Get-Credential -Message "Enter your CyberArk credentials"

# Define variables for the API endpoint
$baseUrl = "https://pvwa.address/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/pkipn/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"
$getAccountPassword = "$baseUrl/Accounts/212_3/Password/Retrieve"

# Load the client certificate from the PIV card
$cert = Get-Item -Path Cert:\CurrentUser\My\49xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx40

# Ensure the certificate is loaded correctly
if (-not $cert) {
    Write-Host "Certificate not found. Please check the thumbprint and ensure your PIV card is inserted."
    exit
}

# Authenticate to the CyberArk REST API to get a session token
try {
    $authResponse = Invoke-RestMethod -Uri $authEndpoint -Method 'POST' -Certificate $cert
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

# Define additional parameters
$parameters = @{
    reason = "Reason"
} | ConvertTo-Json

# Perform POST request for retrieving the account password with additional parameters
$response = Invoke-RestMethod -Uri $getAccountPassword -Method 'POST' -Headers $headers -Body $parameters -ContentType 'application/json'
$response | ConvertTo-Json

# Logoff from session
$response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
Write-Host "Success...logging off"
