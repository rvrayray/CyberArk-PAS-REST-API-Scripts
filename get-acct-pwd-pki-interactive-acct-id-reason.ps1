# Utilize the Get-Credential cmdlet to prompt for Windows authentication
$cred = Get-Credential -Message "Enter your CyberArk credentials"

# Define variables for the API endpoint
$baseUrl = "https://cyberpass-dev.ba.ssa.gov/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/pkipn/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"

# Prompt the user to enter the account ID
$accountID = Read-Host -Prompt "Enter the account ID"

# Construct the URL for retrieving the account password dynamically
$getAccountPassword = "$baseUrl/Accounts/$accountID/Password/Retrieve"

# Load the client certificate from the PIV card
$cert = Get-Item -Path Cert:\CurrentUser\My\495240dd341a2a3fac0651f2695c541fb5b09840

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

# Prompt the user for the reason for accessing the password
$userReason = Read-Host -Prompt "Enter the reason for accessing the password"

# Define additional parameters
$Parameters = @{
	reason = $userReason
} | ConvertTo-Json

# Perform POST request for retrieving the account password 
try {
    $response = Invoke-RestMethod -Uri $getAccountPassword -Method 'POST' -Headers $headers -Body $parameters -ContentType 'application/json'
    $response | ConvertTo-Json
} catch {
    Write-Host "Failed to retrieve the password for account ID $accountID. Please check the account ID and try again."
    exit
}

# Log off from session
$response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
Write-Host "Success...logging off"
