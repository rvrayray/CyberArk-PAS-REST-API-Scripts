# Get-CyberArkAccountDetails-PIV.ps1
# Searches for an account and returns full details including last password change
# Uses PIV card (certificate-based) authentication

$PVWAUrl = "https://pvwa.acme.lab"

# Ignore SSL errors
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# PIV Card Authentication
Write-Host ""
Write-Host "Insert your PIV card and press Enter to continue..." -ForegroundColor Cyan
Read-Host

# Open Windows certificate picker to select PIV cert
Write-Host "Select your PIV certificate from the dialog..." -ForegroundColor Cyan
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open("ReadOnly")

$certs = $store.Certificates | Where-Object {
    $_.HasPrivateKey -and
    $_.NotAfter -gt (Get-Date) -and
    ($_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.4.1.311.20.2.2" -or  # Smart Card Logon
     $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.2")           # Client Authentication
}

if ($certs.Count -eq 0) {
    Write-Host "No valid PIV certificates found. Make sure your card is inserted." -ForegroundColor Red
    exit 1
}

# If multiple certs let user pick
if ($certs.Count -gt 1) {
    Write-Host ""
    Write-Host "Multiple certificates found:" -ForegroundColor Cyan
    $i = 1
    $certs | ForEach-Object {
        Write-Host "  [$i] $($_.Subject) (Expires: $($_.NotAfter.ToString('yyyy-MM-dd')))"
        $i++
    }
    $selection = Read-Host "Select certificate number"
    $cert = $certs[$selection - 1]
} else {
    $cert = $certs[0]
}

Write-Host "Using certificate: $($cert.Subject)" -ForegroundColor Green

# Authenticate to CyberArk using PKI/certificate auth
try {
    $token = Invoke-RestMethod `
        -Uri "$PVWAUrl/PasswordVault/API/auth/pkipin/Logon" `
        -Method POST `
        -Certificate $cert `
        -ContentType "application/json" `
        -Body "{}"

    Write-Host "Authentication successful." -ForegroundColor Green
} catch {
    # Try alternate PKI endpoint
    try {
        $token = Invoke-RestMethod `
            -Uri "$PVWAUrl/PasswordVault/API/auth/pki/Logon" `
            -Method POST `
            -Certificate $cert `
            -ContentType "application/json" `
            -Body "{}"
        Write-Host "Authentication successful." -ForegroundColor Green
    } catch {
        Write-Host "PIV authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Prompt for search term
$searchTerm = Read-Host "Enter account name to search for"

# Search accounts
$results = Invoke-RestMethod `
    -Uri "$PVWAUrl/PasswordVault/API/Accounts?search=$searchTerm" `
    -Method GET `
    -Headers @{ Authorization = $token }

if ($results.count -eq 0) {
    Write-Host "No accounts found matching '$searchTerm'" -ForegroundColor Yellow
    Invoke-RestMethod -Uri "$PVWAUrl/PasswordVault/API/Auth/Logoff" -Method POST -Headers @{ Authorization = $token } | Out-Null
    exit
}

# If multiple results let user pick one
if ($results.count -gt 1) {
    Write-Host ""
    Write-Host "Multiple accounts found:" -ForegroundColor Cyan
    $i = 1
    $results.value | ForEach-Object {
        Write-Host "  [$i] $($_.userName) @ $($_.address) (Safe: $($_.safeName))"
        $i++
    }
    Write-Host ""
    $selection = Read-Host "Select account number"
    $account = $results.value[$selection - 1]
} else {
    $account = $results.value[0]
}

# Get full account details by ID
$details = Invoke-RestMethod `
    -Uri "$PVWAUrl/PasswordVault/API/Accounts/$($account.id)" `
    -Method GET `
    -Headers @{ Authorization = $token }

# Convert Unix timestamps to readable dates
function Convert-UnixTime {
    param([long]$unixTime)
    if ($unixTime -eq 0 -or $null -eq $unixTime) { return "Never" }
    return (Get-Date "1970-01-01 00:00:00").AddSeconds($unixTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
}

# Display results
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Account Details" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Account ID          : $($details.id)" -ForegroundColor Green
Write-Host "  Username            : $($details.userName)"
Write-Host "  Address             : $($details.address)"
Write-Host "  Safe                : $($details.safeName)"
Write-Host "  Platform            : $($details.platformId)"
Write-Host "  Status              : $($details.secretManagement.status)"
Write-Host ""
Write-Host "  Last Password Change: $(Convert-UnixTime $details.secretManagement.lastModifiedTime)" -ForegroundColor Yellow
Write-Host "  Last Verified       : $(Convert-UnixTime $details.secretManagement.lastVerifiedTime)" -ForegroundColor Yellow
Write-Host "  Last Reconciled     : $(Convert-UnixTime $details.secretManagement.lastReconciledTime)" -ForegroundColor Yellow
Write-Host ""

# Logoff
Invoke-RestMethod -Uri "$PVWAUrl/PasswordVault/API/Auth/Logoff" -Method POST -Headers @{ Authorization = $token } | Out-Null
Write-Host "Done." -ForegroundColor Cyan