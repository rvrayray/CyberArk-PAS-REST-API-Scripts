<#
.SYNOPSIS
    Get-CyberArkAccountDetails-PIV.ps1
    Searches for a CyberArk account and returns full details, including last
    password change / verify / reconcile. Authenticates with a PIV card (PKI).

.USAGE
    .\Get-CyberArkAccountDetails-PIV.ps1
    .\Get-CyberArkAccountDetails-PIV.ps1 -PVWAUrl https://pvwa.example.gov
    .\Get-CyberArkAccountDetails-PIV.ps1 -PVWAUrl https://pvwa.example.gov -SearchTerm svc_splunk

.NOTES
    - No environment URL is hardcoded. Pass -PVWAUrl or enter it at the prompt.
    - On auth failure, prints HTTP status, response body, and inner exceptions
      so you can tell an IIS client-cert rejection from a CyberArk rejection.
    - Works on Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [string]$PVWAUrl,
    [string]$SearchTerm
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
if (-not $PVWAUrl) {
    $PVWAUrl = Read-Host "PVWA base URL (e.g. https://pvwa.domain.gov)"
}
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')
if ($PVWAUrl -notmatch '^https://') {
    Write-Host "PVWA URL must start with https://" -ForegroundColor Red
    exit 1
}

$IsCore = $PSVersionTable.PSVersion.Major -ge 6
Write-Host ""
Write-Host "PowerShell version : $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
Write-Host "PVWA               : $PVWAUrl" -ForegroundColor DarkGray

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# SSL bypass for Windows PowerShell 5.1 (PS7 uses -SkipCertificateCheck instead)
if (-not $IsCore) {
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Invoke-PVWA {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers,
        [string]$Body,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $p = @{
        Uri         = $Uri
        Method      = $Method
        ContentType = 'application/json'
        ErrorAction = 'Stop'
    }
    if ($Headers)     { $p.Headers = $Headers }
    if ($Body)        { $p.Body = $Body }
    if ($Certificate) { $p.Certificate = $Certificate }
    if ($IsCore)      { $p.SkipCertificateCheck = $true }
    Invoke-RestMethod @p
}

function Write-ApiError {
    param($Err)

    Write-Host "  Message : $($Err.Exception.Message)" -ForegroundColor Red

    $resp = $Err.Exception.Response
    if ($resp) {
        Write-Host "  Status  : $([int]$resp.StatusCode) $($resp.StatusCode)" -ForegroundColor Red
    }

    # Response body: ErrorDetails works in both 5.1 and 7; stream read is a 5.1 fallback
    $body = $Err.ErrorDetails.Message
    if (-not $body -and $resp -is [System.Net.HttpWebResponse]) {
        try {
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $body = $sr.ReadToEnd()
            $sr.Close()
        } catch { }
    }

    if ($body) {
        if ($body -match '<html|<!DOCTYPE') {
            Write-Host "  BodyType: HTML  (response came from IIS, not CyberArk)" -ForegroundColor Red
            $body = ($body -replace '(?s)<style.*?</style>', ' ' -replace '<[^>]+>', ' ' -replace '\s+', ' ').Trim()
        } else {
            Write-Host "  BodyType: JSON/text  (response came from CyberArk)" -ForegroundColor Red
        }
        if ($body.Length -gt 500) { $body = $body.Substring(0, 500) + ' ...' }
        Write-Host "  Body    : $body" -ForegroundColor Red
    } else {
        Write-Host "  Body    : (none)" -ForegroundColor Red
    }

    $inner = $Err.Exception.InnerException
    while ($inner) {
        Write-Host "  Inner   : $($inner.Message)" -ForegroundColor Red
        $inner = $inner.InnerException
    }
}

function Convert-UnixTime {
    param($unixTime)
    if (-not $unixTime -or [long]$unixTime -eq 0) { return "Never" }
    return ([DateTimeOffset]::FromUnixTimeSeconds([long]$unixTime)).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
}

# ---------------------------------------------------------------------------
# PIV certificate selection
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Reading certificates from CurrentUser\My (PIV card must be inserted)..." -ForegroundColor Cyan

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open("ReadOnly")
$certs = @($store.Certificates | Where-Object {
    $_.HasPrivateKey -and
    $_.NotAfter -gt (Get-Date) -and
    ($_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.4.1.311.20.2.2" -or   # Smart Card Logon
     $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.2")            # Client Authentication
})
$store.Close()

if ($certs.Count -eq 0) {
    Write-Host "No valid client-auth certificates found. Is the PIV card inserted and the middleware running?" -ForegroundColor Red
    exit 1
}

# Prefer the actual PIV Authentication cert when present
$pivCerts = @($certs | Where-Object { $_.Subject -match 'dnQualifier=PIV' })
if ($pivCerts.Count -gt 0) { $certs = $pivCerts }

if ($certs.Count -gt 1) {
    Write-Host ""
    Write-Host "Multiple certificates found:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $certs.Count; $i++) {
        Write-Host "  [$($i + 1)] $($certs[$i].Subject) (Expires: $($certs[$i].NotAfter.ToString('yyyy-MM-dd')))"
    }
    $selection = [int](Read-Host "Select certificate number")
    if ($selection -lt 1 -or $selection -gt $certs.Count) {
        Write-Host "Invalid selection." -ForegroundColor Red
        exit 1
    }
    $cert = $certs[$selection - 1]
} else {
    $cert = $certs[0]
}

Write-Host "Using certificate : $($cert.Subject)" -ForegroundColor Green
Write-Host "Issuer            : $($cert.Issuer)" -ForegroundColor DarkGray
Write-Host "Thumbprint        : $($cert.Thumbprint)" -ForegroundColor DarkGray
Write-Host "Watch for a Windows PIN prompt during the next step." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Authenticate (PKI, then PKIPN)
# ---------------------------------------------------------------------------
$token = $null
foreach ($ep in @("pki", "pkipn")) {
    $uri = "$PVWAUrl/PasswordVault/API/auth/$ep/Logon"
    Write-Host ""
    Write-Host "Trying $uri ..." -ForegroundColor Cyan
    try {
        $token = Invoke-PVWA -Uri $uri -Method POST -Certificate $cert -Body "{}"
        $token = "$token".Trim().Trim('"')
        Write-Host "Authentication successful via $ep." -ForegroundColor Green
        break
    } catch {
        Write-ApiError $_
    }
}

if (-not $token) {
    Write-Host ""
    Write-Host "PIV authentication failed on all endpoints." -ForegroundColor Red
    exit 1
}

$authHeader = @{ Authorization = $token }

# ---------------------------------------------------------------------------
# Search and display
# ---------------------------------------------------------------------------
try {
    if (-not $SearchTerm) {
        $SearchTerm = Read-Host "Enter account name to search for"
    }
    $encoded = [uri]::EscapeDataString($SearchTerm)

    $results = Invoke-PVWA -Uri "$PVWAUrl/PasswordVault/API/Accounts?search=$encoded" -Headers $authHeader
    $accounts = @($results.value)

    if ($accounts.Count -eq 0) {
        Write-Host "No accounts found matching '$SearchTerm'" -ForegroundColor Yellow
        return
    }

    if ($accounts.Count -gt 1) {
        Write-Host ""
        Write-Host "Multiple accounts found:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $accounts.Count; $i++) {
            $a = $accounts[$i]
            Write-Host "  [$($i + 1)] $($a.userName) @ $($a.address) (Safe: $($a.safeName))"
        }
        Write-Host ""
        $selection = [int](Read-Host "Select account number")
        if ($selection -lt 1 -or $selection -gt $accounts.Count) {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
        $account = $accounts[$selection - 1]
    } else {
        $account = $accounts[0]
    }

    $details = Invoke-PVWA -Uri "$PVWAUrl/PasswordVault/API/Accounts/$($account.id)" -Headers $authHeader

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
}
catch {
    Write-Host "API call failed:" -ForegroundColor Red
    Write-ApiError $_
}
finally {
    try {
        Invoke-PVWA -Uri "$PVWAUrl/PasswordVault/API/Auth/Logoff" -Method POST -Headers $authHeader | Out-Null
    } catch { }
    Write-Host "Done." -ForegroundColor Cyan
}
