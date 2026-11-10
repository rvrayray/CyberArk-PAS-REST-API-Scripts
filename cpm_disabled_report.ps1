#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a report of accounts with CPM automatic management disabled
    (CyberArk PAS self-hosted, Gen2 REST API).

.DESCRIPTION
    Authenticates to the PVWA, enumerates accounts, and exports every account
    where secretManagement.automaticManagementEnabled is false. Each row is
    classified as disabled by the CPM (reason starts with "(CPM)") or by a user.

    Two collection modes:
      - Default      : pages through all accounts and filters client-side
                       (works on any version with the Gen2 Accounts API).
      - -UseSavedFilter : asks the PVWA for its built-in DisabledPasswordByCPM /
                       DisabledPasswordByUser views (newer versions only).
                       Falls back to full enumeration if the PVWA rejects it.

    The report only contains accounts in safes where the API user holds
    List Accounts. Run it as a user with broad safe membership.

.PARAMETER PVWAUrl
    Base PVWA URL, e.g. https://pvwa.acme.lab/PasswordVault

.PARAMETER AuthType
    CyberArk, LDAP, RADIUS or Windows. Windows uses the current logon session
    (integrated auth) and ignores -Credential.

.PARAMETER Credential
    API user credential. Prompted for if omitted (except with Windows auth).

.PARAMETER DisabledBy
    All (default), CPM or User.

.PARAMETER SafeName
    Limit the report to one safe.

.PARAMETER UseSavedFilter
    Use the PVWA saved filters instead of enumerating every account.

.PARAMETER OutputPath
    CSV path. Defaults to .\CPM_Disabled_Report_<timestamp>.csv

.PARAMETER LogPath
    Log file path. Defaults to .\CPM_Disabled_Report_<timestamp>.log

.PARAMETER PageSize
    Accounts per API call (1-1000). Default 1000.

.PARAMETER SkipCertificateCheck
    Ignore TLS certificate errors. Lab use only.

.PARAMETER SmtpServer
    If set (with -MailFrom and -MailTo), the CSV is emailed when the run finishes.

.EXAMPLE
    .\cpm_disabled.ps1
    Runs against the default PVWA (https://pvwa.acme.lab/PasswordVault) with LDAP auth.

.EXAMPLE
    .\cpm_disabled.ps1 -AuthType CyberArk -DisabledBy CPM -SkipCertificateCheck

.EXAMPLE
    .\Get-CPMDisabledReport.ps1 -PVWAUrl https://pvwa.acme.lab/PasswordVault -DisabledBy CPM -UseSavedFilter `
        -SmtpServer smtp.acme.lab -MailFrom pam-reports@acme.lab -MailTo pam-team@acme.lab

.NOTES
    Exit codes: 0 = success, 1 = failure.
    Not tested against your environment - validate in the lab before production use.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^https?://')]
    [string]$PVWAUrl = 'https://pvwa.acme.lab/PasswordVault',

    [ValidateSet('CyberArk', 'LDAP', 'RADIUS', 'Windows')]
    [string]$AuthType = 'LDAP',

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateSet('All', 'CPM', 'User')]
    [string]$DisabledBy = 'All',

    [string]$SafeName,

    [switch]$UseSavedFilter,

    [string]$OutputPath,

    [string]$LogPath,

    [ValidateRange(1, 1000)]
    [int]$PageSize = 1000,

    [switch]$SkipCertificateCheck,

    [string]$SmtpServer,
    [int]$SmtpPort = 25,
    [string]$MailFrom,
    [string[]]$MailTo,
    [switch]$SmtpUseSsl,
    [System.Management.Automation.PSCredential]$SmtpCredential
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) "CPM_Disabled_Report_$stamp.csv" }
if (-not $LogPath)    { $LogPath    = Join-Path (Get-Location) "CPM_Disabled_Report_$stamp.log" }

# Accept a pasted UI address (e.g. .../PasswordVault/v10/logon/ldap) and trim it to the base URL.
$PVWAUrl  = ($PVWAUrl -replace '(?i)(/PasswordVault)(/.*)?$', '$1').TrimEnd('/')
$isCore   = $PSVersionTable.PSVersion.Major -ge 6
$session  = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$headers  = @{}
$loggedOn = $false
$exitCode = 0

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function Get-ApiErrorText {
    # Pulls ErrorCode / ErrorMessage out of a PVWA error response when present.
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    $text = $ErrorRecord.Exception.Message
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $j = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json
            $code = $null; $msg = $null
            if ($j.PSObject.Properties['ErrorCode'])    { $code = $j.ErrorCode }
            if ($j.PSObject.Properties['ErrorMessage']) { $msg  = $j.ErrorMessage }
            if ($code -or $msg) { $text = ('{0} {1}' -f $code, $msg).Trim() }
        }
    } catch { }
    return $text
}

function Invoke-Pvwa {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Method = 'Get',
        [string]$Body,
        [switch]$DefaultCredentials
    )
    $p = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $headers
        WebSession  = $session
        ContentType = 'application/json'
        TimeoutSec  = 300
    }
    if ($Body)               { $p.Body = $Body }
    if ($DefaultCredentials) { $p.UseDefaultCredentials = $true }
    if ($isCore -and $SkipCertificateCheck) { $p.SkipCertificateCheck = $true }
    Invoke-RestMethod @p
}

function Convert-Epoch {
    param($Seconds)
    if ($null -eq $Seconds -or "$Seconds" -eq '' -or "$Seconds" -eq '0') { return $null }
    try { return [DateTimeOffset]::FromUnixTimeSeconds([int64]$Seconds).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss') }
    catch { return $null }
}

function Get-Prop {
    # StrictMode-safe property read.
    param($Object, [string]$Name)
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $null
}

function Get-AccountPages {
    # Follows nextLink until the result set is exhausted.
    param([Parameter(Mandatory = $true)][string]$Query, [string]$Label = 'accounts')
    $results = New-Object System.Collections.Generic.List[object]
    $url  = "$PVWAUrl/API/Accounts?$Query"
    $page = 0
    while ($url) {
        $page++
        $r = Invoke-Pvwa -Uri $url
        $value = Get-Prop $r 'value'
        if ($value) { foreach ($a in $value) { $results.Add($a) } }
        Write-Log ("  {0}: page {1}, {2} retrieved so far" -f $Label, $page, $results.Count)
        $next = Get-Prop $r 'nextLink'
        if ($next) { $url = '{0}/{1}' -f $PVWAUrl, $next.TrimStart('/') } else { $url = $null }
    }
    return ,$results
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
try {
    Write-Log "Starting CPM disabled report against $PVWAUrl (auth: $AuthType, scope: $DisabledBy)"

    # TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($SkipCertificateCheck) {
        Write-Log 'TLS certificate validation is DISABLED for this run' 'WARN'
        if (-not $isCore) {
            if (-not ('TrustAllCertsPolicy' -as [type])) {
                Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
'@
            }
            [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }

    # Email parameter sanity check before doing any work
    $sendMail = [bool]$SmtpServer
    if ($sendMail -and (-not $MailFrom -or -not $MailTo)) {
        throw '-SmtpServer requires both -MailFrom and -MailTo.'
    }

    # ---- Logon -------------------------------------------------------------
    $logonUrl = "$PVWAUrl/API/auth/$AuthType/Logon"
    if ($AuthType -eq 'Windows') {
        $token = Invoke-Pvwa -Uri $logonUrl -Method Post -DefaultCredentials
    }
    else {
        if (-not $Credential) { $Credential = Get-Credential -Message "PVWA credentials ($AuthType)" }
        if (-not $Credential) { throw 'No credential supplied.' }
        $body = @{
            username          = $Credential.UserName
            password          = $Credential.GetNetworkCredential().Password
            concurrentSession = $true
        } | ConvertTo-Json
        try {
            $token = Invoke-Pvwa -Uri $logonUrl -Method Post -Body $body
        }
        catch {
            $errText = Get-ApiErrorText $_
            # RADIUS challenge-response: PVWA answers ITATS542I and expects the
            # challenge reply as the password on the same web session.
            if ($AuthType -eq 'RADIUS' -and $errText -match 'ITATS542I') {
                Write-Log 'RADIUS challenge received'
                $otp = Read-Host -Prompt 'RADIUS challenge response (OTP)' -AsSecureString
                $otpPlain = (New-Object System.Management.Automation.PSCredential('x', $otp)).GetNetworkCredential().Password
                $body = @{
                    username          = $Credential.UserName
                    password          = $otpPlain
                    concurrentSession = $true
                } | ConvertTo-Json
                $token = Invoke-Pvwa -Uri $logonUrl -Method Post -Body $body
                $otpPlain = $null
            }
            else { throw "Logon failed: $errText" }
        }
        finally { $body = $null }
    }
    if (-not $token) { throw 'Logon returned no session token.' }
    $headers = @{ Authorization = "$token" }
    $loggedOn = $true
    Write-Log 'Logon successful'

    # ---- Collect -----------------------------------------------------------
    $raw = $null
    if ($UseSavedFilter) {
        $filters = @()
        if ($DisabledBy -in 'All', 'CPM')  { $filters += 'DisabledPasswordByCPM' }
        if ($DisabledBy -in 'All', 'User') { $filters += 'DisabledPasswordByUser' }
        try {
            $raw = New-Object System.Collections.Generic.List[object]
            foreach ($f in $filters) {
                Write-Log "Querying saved filter $f"
                $set = Get-AccountPages -Query "savedFilter=$f&limit=$PageSize" -Label $f
                foreach ($a in $set) { $raw.Add($a) }
            }
        }
        catch {
            Write-Log ("Saved filter query failed ({0}). Falling back to full enumeration." -f (Get-ApiErrorText $_)) 'WARN'
            $raw = $null
        }
    }
    if ($null -eq $raw) {
        $query = "limit=$PageSize"
        if ($SafeName) { $query += '&filter=' + [uri]::EscapeDataString("safeName eq $SafeName") }
        Write-Log 'Enumerating accounts (client-side filter)'
        $raw = Get-AccountPages -Query $query -Label 'accounts'
    }
    Write-Log ("Retrieved {0} account record(s) from the PVWA" -f $raw.Count)

    # ---- Filter / shape ----------------------------------------------------
    $seen   = @{}
    $report = New-Object System.Collections.Generic.List[object]
    foreach ($a in $raw) {
        $sm = Get-Prop $a 'secretManagement'
        if ($null -eq $sm) { continue }
        if ((Get-Prop $sm 'automaticManagementEnabled') -ne $false) { continue }

        $id = Get-Prop $a 'id'
        if ($id -and $seen.ContainsKey($id)) { continue }
        if ($id) { $seen[$id] = $true }

        $safe = Get-Prop $a 'safeName'
        if ($SafeName -and $safe -ne $SafeName) { continue }

        $reason = Get-Prop $sm 'manualManagementReason'
        if ($reason -and "$reason".TrimStart().StartsWith('(CPM)')) { $by = 'CPM' } else { $by = 'User' }
        if ($DisabledBy -ne 'All' -and $by -ne $DisabledBy) { continue }

        $report.Add([pscustomobject]@{
            AccountId        = $id
            SafeName         = $safe
            PlatformId       = Get-Prop $a 'platformId'
            Address          = Get-Prop $a 'address'
            UserName         = Get-Prop $a 'userName'
            AccountName      = Get-Prop $a 'name'
            DisabledBy       = $by
            Reason           = $reason
            Status           = Get-Prop $sm 'status'
            LastModifiedTime = Convert-Epoch (Get-Prop $sm 'lastModifiedTime')
            LastVerifiedTime = Convert-Epoch (Get-Prop $sm 'lastVerifiedTime')
            LastReconciled   = Convert-Epoch (Get-Prop $sm 'lastReconciledTime')
            CreatedTime      = Convert-Epoch (Get-Prop $a 'createdTime')
        })
    }

    # ---- Output ------------------------------------------------------------
    $sorted = @($report | Sort-Object SafeName, Address, UserName)
    if ($sorted.Count -gt 0) {
        $sorted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    }
    else {
        # Header-only file so downstream consumers always get a CSV.
        '"AccountId","SafeName","PlatformId","Address","UserName","AccountName","DisabledBy","Reason","Status","LastModifiedTime","LastVerifiedTime","LastReconciled","CreatedTime"' |
            Set-Content -Path $OutputPath -Encoding UTF8
    }

    $cpmCount  = @($sorted | Where-Object { $_.DisabledBy -eq 'CPM' }).Count
    $userCount = @($sorted | Where-Object { $_.DisabledBy -eq 'User' }).Count
    Write-Log ("CPM-disabled accounts: {0} total ({1} by CPM, {2} by user)" -f $sorted.Count, $cpmCount, $userCount)
    $topSafes = $sorted | Group-Object SafeName | Sort-Object Count -Descending | Select-Object -First 10
    foreach ($g in $topSafes) { Write-Log ("  {0,-40} {1}" -f $g.Name, $g.Count) }
    Write-Log "Report written to $OutputPath"

    # ---- Email -------------------------------------------------------------
    if ($sendMail) {
        try {
            $mail = @{
                SmtpServer  = $SmtpServer
                Port        = $SmtpPort
                From        = $MailFrom
                To          = $MailTo
                Subject     = ("CyberArk CPM Disabled Report - {0} account(s) - {1}" -f $sorted.Count, (Get-Date -Format 'yyyy-MM-dd'))
                Body        = ("PVWA: {0}`r`nScope: {1}`r`nTotal: {2}`r`nDisabled by CPM: {3}`r`nDisabled by user: {4}`r`n`r`nReport attached." -f $PVWAUrl, $DisabledBy, $sorted.Count, $cpmCount, $userCount)
                Attachments = $OutputPath
            }
            if ($SmtpUseSsl)     { $mail.UseSsl = $true }
            if ($SmtpCredential) { $mail.Credential = $SmtpCredential }
            Send-MailMessage @mail -WarningAction SilentlyContinue
            Write-Log ("Report emailed to {0}" -f ($MailTo -join ', '))
        }
        catch {
            Write-Log ("Email failed: {0}" -f $_.Exception.Message) 'ERROR'
            $exitCode = 1
        }
    }
}
catch {
    $msg = $_.Exception.Message
    if ($_.ErrorDetails) { $msg = Get-ApiErrorText $_ }
    Write-Log "FAILED: $msg" 'ERROR'
    $exitCode = 1
}
finally {
    if ($loggedOn) {
        try {
            Invoke-Pvwa -Uri "$PVWAUrl/API/auth/Logoff" -Method Post | Out-Null
            Write-Log 'Logged off'
        }
        catch { Write-Log ("Logoff failed: {0}" -f $_.Exception.Message) 'WARN' }
    }
    $headers = @{}
    $token = $null
}

exit $exitCode
