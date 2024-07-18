#Define variables for the API endpoint
$baseUrl = "https://pvwa.address.com/PasswordVault/API"
$authEndpoint = "$baseUrl/auth/pkipn/Logon"
$logoffEndpoint = "$baseUrl/auth/logoff"
$getAccountDetails = "$baseUrl/Accounts/93_3"

# Load the client certificate from the PIV card
$cert = Get-Item -Path Cert:\CurrentUser\My\4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0

# Ensure the certificate is loaded correctly
if (-not $cert) {
    Write-Host "Certificate not found. Please check the thumbprint and ensure your PIV card is inserted."
    exit
}

# Authenticate to the CyberArk REST API using the client certificate to get a session token
try {
    $authResponse = Invoke-RestMethod -Uri $authEndpoint -Method 'POST' -Certificate $cert
    $sessionToken = $authResponse
    Write-Host "Successfully authenticated."
} catch {
    Write-Host "Failed to authenticate. Please check your PIV card and try again."
    exit

}

#Create the headers for the GET requests using the session token
$headers = @{
    "Authorization" = $sessionToken
    "Content-Type" = "application/json"
}

#Perform GET request for Account Details 
$response = Invoke-RestMethod -Uri $getAccountDetails -Method 'GET' -Headers $headers
$response | ConvertTo-Json

#Logoff from session
$response = Invoke-RestMethod -Uri $logoffEndpoint -Method 'POST' -Headers $headers
Write-Host "Success...logging off"
