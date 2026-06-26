# SAST Test File – PowerShell
# Intentional OWASP Top 10 (2021) vulnerabilities for SAST tool evaluation.
# !! DO NOT USE IN PRODUCTION !!

#Requires -Version 3.0

# =========================================================
# [A02] Cryptographic Failures – Hardcoded Secrets
# =========================================================
$global:DbPassword      = "P@ssw0rd123"          # [VULN-P-A02-1] Hardcoded DB password
$global:SecretKey       = "MySuperSecretKey12345" # [VULN-P-A02-2] Hardcoded encryption key
$global:ApiKey          = "sk-abcdef1234567890"   # [VULN-P-A02-3] Hardcoded API key
$global:AdminPassword   = "admin123"              # [VULN-P-A07-1] Hardcoded admin credential

# [A02] Weak hashing – MD5, no salt
function Get-MD5Hash {
    param([string]$InputString)
    # [VULN-P-A02-4] MD5 is cryptographically broken; no salt applied
    $md5  = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLower()
}

# [A02] Storing credentials in plaintext file
function Save-Credentials {
    param([string]$Username, [string]$Password)
    # [VULN-P-A02-5] Credentials written in cleartext to disk
    "$Username`:$Password" | Out-File -FilePath "C:\app\credentials.txt" -Append
}

# [A02] Disabled TLS certificate validation
function Invoke-InsecureWebRequest {
    param([string]$Url)
    # [VULN-P-A02-6] All SSL/TLS certificate errors silently ignored
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    return (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
}

# =========================================================
# [A03] Injection – SQL Injection
# =========================================================
function Get-UserByName {
    param([string]$Username)
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    # [VULN-P-A03-1] SQL injection: Username interpolated directly into query
    $query = "SELECT * FROM users WHERE username = '$Username'"
    $cmd   = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
    return $cmd.ExecuteReader()
}

# [A03] OS Command Injection via Invoke-Expression
function Invoke-Diagnostic {
    param([string]$HostName)
    # [VULN-P-A03-2] Command injection: HostName appended to shell command unsanitized
    $result = Invoke-Expression "ping -n 1 $HostName"
    return $result
}

# [A03] Arbitrary PowerShell code execution via Invoke-Expression (eval equivalent)
function Invoke-UserScript {
    param([string]$UserCode)
    # [VULN-P-A03-3] Arbitrary PowerShell code execution – code injection
    Invoke-Expression $UserCode
}

# [A03] Script Block Injection via [ScriptBlock]::Create
function Run-DynamicCommand {
    param([string]$CommandString)
    # [VULN-P-A03-4] Script block injection; user controls entire command body
    $sb = [ScriptBlock]::Create($CommandString)
    & $sb
}

# =========================================================
# [A01] Broken Access Control
# =========================================================
function Get-Document {
    param([string]$DocId)
    # [VULN-P-A01-1] No authorization check; any caller can retrieve any document
    # [VULN-P-A01-2] Path traversal: DocId may contain "..\..\" to escape root
    $path = "C:\app\documents\$DocId"
    return Get-Content -Path $path -Raw
}

function Remove-User {
    param([string]$UserId)
    # [VULN-P-A01-3] No check that calling principal holds admin role
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "DELETE FROM users WHERE id = '$UserId'", $conn)
    $cmd.ExecuteNonQuery()
}

function Get-AdminReport {
    # [VULN-P-A01-4] Admin endpoint with no authentication or role check
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand("SELECT * FROM admin_logs", $conn)
    return $cmd.ExecuteReader()
}

# =========================================================
# [A07] Identification and Authentication Failures
# =========================================================
function Test-Login {
    param([string]$Username, [string]$Password)
    # [VULN-P-A07-2] Hardcoded backdoor credentials bypass real authentication
    if ($Username -eq "admin" -and $Password -eq "admin123") {
        return $true
    }
    # [VULN-P-A07-3] No account lockout or brute-force throttling
    $hashedInput = Get-MD5Hash -InputString $Password
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    # [VULN-P-A07-4] MD5-hashed (weak) passwords stored and compared
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "SELECT COUNT(*) FROM users WHERE username='$Username' AND password_md5='$hashedInput'", $conn)
    return ($cmd.ExecuteScalar() -gt 0)
}

function New-SessionToken {
    param([string]$UserId)
    # [VULN-P-A07-5] Predictable session token: user ID + Unix milliseconds
    return "SESSION_${UserId}_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
}

# =========================================================
# [A08] Software and Data Integrity Failures
# =========================================================
function Import-SerializedObject {
    param([string]$Base64Data)
    # [VULN-P-A08-1] BinaryFormatter deserialization of untrusted data → RCE
    # BinaryFormatter is banned in .NET 5+ due to known RCE risk
    $bytes = [System.Convert]::FromBase64String($Base64Data)
    $ms    = New-Object System.IO.MemoryStream (, $bytes)
    $bf    = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
    return $bf.Deserialize($ms)
}

function Install-UpdatePackage {
    param([string]$PackageUrl)
    # [VULN-P-A08-2] Update package downloaded and executed with no hash or signature check
    $localPath = "$env:TEMP\update.msi"
    Invoke-WebRequest -Uri $PackageUrl -OutFile $localPath -UseBasicParsing
    # No integrity check performed before execution
    Start-Process -FilePath $localPath -ArgumentList "/quiet" -Wait
}

function Import-ExternalModule {
    param([string]$ModuleUrl)
    # [VULN-P-A08-3] Remote PowerShell module loaded without signature verification
    $code = (Invoke-WebRequest -Uri $ModuleUrl -UseBasicParsing).Content
    Invoke-Expression $code  # executing untrusted remote code
}

# =========================================================
# [A09] Security Logging and Monitoring Failures
# =========================================================
function Write-LoginLog {
    param([string]$Username, [string]$Password, [bool]$Success)
    # [VULN-P-A09-1] Plaintext password recorded in log file
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') user=$Username password=$Password success=$Success"
    Add-Content -Path "C:\logs\auth.log" -Value $entry
    Write-Host $entry
}

function Write-PaymentLog {
    param([string]$CardNumber, [double]$Amount, [string]$CVV)
    # [VULN-P-A09-2] Full PAN and CVV logged – PCI DSS violation
    Add-Content -Path "C:\logs\payments.log" -Value `
        "$(Get-Date) card=$CardNumber cvv=$CVV amount=$Amount"
}

function Write-ApiLog {
    param([hashtable]$RequestParams)
    # [VULN-P-A09-3] All request parameters (may include secrets) logged verbatim
    Add-Content -Path "C:\logs\api.log" -Value ($RequestParams | ConvertTo-Json -Compress)
}

# =========================================================
# [A10] Server-Side Request Forgery (SSRF)
# =========================================================
function Invoke-RemoteFetch {
    param([string]$UserSuppliedUrl)
    # [VULN-P-A10-1] No URL allowlist; attacker can reach internal services
    # e.g., http://169.254.169.254/latest/meta-data/ on cloud VMs
    return (Invoke-WebRequest -Uri $UserSuppliedUrl -UseBasicParsing).Content
}

function Get-UserAvatar {
    param([string]$AvatarUrl)
    # [VULN-P-A10-2] SSRF via user-controlled image URL (can probe internal network)
    $response = Invoke-WebRequest -Uri $AvatarUrl -UseBasicParsing
    return $response.Content
}

function Send-Webhook {
    param([string]$WebhookUrl, [string]$Payload)
    # [VULN-P-A10-3] Webhook destination not validated against allowlist
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Payload -ContentType "application/json"
}

# =========================================================
# [A05] Security Misconfiguration
# =========================================================

# [VULN-P-A05-1] SSLv3 enabled – vulnerable to POODLE attack
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3

function Invoke-Request {
    param([object]$Request)
    try {
        # ... process request ...
        Write-Output "OK"
    }
    catch {
        # [VULN-P-A05-2] Full exception details and stack trace returned to caller
        Write-Output "Error: $($_.Exception.Message)"
        Write-Output "Stack: $($_.ScriptStackTrace)"
        return $_.Exception
    }
}

# [VULN-P-A05-3] Debug mode and verbose output expose internal configuration
$DebugPreference    = "Continue"        # [VULN-P-A05-3]
$VerbosePreference  = "Continue"        # [VULN-P-A05-4]
$global:CorsOrigin  = "*"              # [VULN-P-A05-5] Wildcard CORS
$global:CookieSecure = $false          # [VULN-P-A05-6] Cookie not restricted to HTTPS

# =========================================================
# [A04] Insecure Design – Missing Business Logic Controls
# =========================================================
function Transfer-Funds {
    param([string]$FromAcc, [string]$ToAcc, [double]$Amount)
    # [VULN-P-A04-1] Negative $Amount not checked → reverse-transfer attack
    # [VULN-P-A04-2] No rate limiting → automated rapid transfers
    # [VULN-P-A04-3] No idempotency token → duplicate transfers on client retry
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "UPDATE accounts SET balance = balance - $Amount WHERE id = '$FromAcc'", $conn)
    $cmd.ExecuteNonQuery()
    $cmd.CommandText = "UPDATE accounts SET balance = balance + $Amount WHERE id = '$ToAcc'"
    $cmd.ExecuteNonQuery()
}

function Apply-Coupon {
    param([string]$UserId, [string]$CouponCode)
    # [VULN-P-A04-4] No check if coupon already redeemed; allows unlimited reuse
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "UPDATE orders SET discount = 100 WHERE user_id = '$UserId'", $conn)
    $cmd.ExecuteNonQuery()
}

# =========================================================
# [A06] Vulnerable and Outdated Components
# =========================================================

# [VULN-P-A06-1] Running on Windows PowerShell 2.0 – lacks Constrained Language Mode,
#                 AMSI, and ScriptBlock logging available in PS 5.1+
# [VULN-P-A06-2] No module signature enforcement (AllSigned policy not set)
# [VULN-P-A06-3] NuGet packages used (packages.config):
#   - Newtonsoft.Json 6.0.1 with TypeNameHandling.All → deserialization RCE
#   - BouncyCastle 1.8.1 → known vulnerabilities patched in 2.x
# [VULN-P-A06-4] No automated SCA scanning in CI/CD pipeline

function Get-ComponentInfo {
    # [VULN-P-A06-5] PSGallery modules installed without -AllowPrerelease safety checks
    return @{
        "PowerShellVersion"  = $PSVersionTable.PSVersion.ToString()
        "DotNetVersion"      = [System.Environment]::Version.ToString()
        "NewtonsoftJson"     = "6.0.1"  # vulnerable version
        "BouncyCastle"       = "1.8.1"  # vulnerable version
        "ExecutionPolicy"    = (Get-ExecutionPolicy).ToString()
    }
}

Write-Host "=== SAST Vulnerability Test – PowerShell (OWASP Top 10 2021) ==="
