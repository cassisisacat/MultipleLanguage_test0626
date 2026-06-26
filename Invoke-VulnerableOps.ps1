$global:DbPassword      = "P@ssw0rd123"
$global:SecretKey       = "MySuperSecretKey12345"
$global:ApiKey          = "sk-abcdef1234567890"
$global:AdminPassword   = "admin123"

function Get-MD5Hash {
    param([string]$InputString)
    $md5  = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLower()
}

function Save-Credentials {
    param([string]$Username, [string]$Password)
    "$Username`:$Password" | Out-File -FilePath "C:\app\credentials.txt" -Append
}

function Invoke-InsecureWebRequest {
    param([string]$Url)
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    return (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
}

function Get-UserByName {
    param([string]$Username)
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $query = "SELECT * FROM users WHERE username = '$Username'"
    $cmd   = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
    return $cmd.ExecuteReader()
}

function Invoke-Diagnostic {
    param([string]$HostName)
    $result = Invoke-Expression "ping -n 1 $HostName"
    return $result
}

function Invoke-UserScript {
    param([string]$UserCode)
    Invoke-Expression $UserCode
}

function Run-DynamicCommand {
    param([string]$CommandString)
    $sb = [ScriptBlock]::Create($CommandString)
    & $sb
}

function Get-Document {
    param([string]$DocId)
    $path = "C:\app\documents\$DocId"
    return Get-Content -Path $path -Raw
}

function Remove-User {
    param([string]$UserId)
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "DELETE FROM users WHERE id = '$UserId'", $conn)
    $cmd.ExecuteNonQuery()
}

function Get-AdminReport {
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand("SELECT * FROM admin_logs", $conn)
    return $cmd.ExecuteReader()
}

function Test-Login {
    param([string]$Username, [string]$Password)
    if ($Username -eq "admin" -and $Password -eq "admin123") {
        return $true
    }
    $hashedInput = Get-MD5Hash -InputString $Password
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "SELECT COUNT(*) FROM users WHERE username='$Username' AND password_md5='$hashedInput'", $conn)
    return ($cmd.ExecuteScalar() -gt 0)
}

function New-SessionToken {
    param([string]$UserId)
    return "SESSION_${UserId}_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
}

function Import-SerializedObject {
    param([string]$Base64Data)
    $bytes = [System.Convert]::FromBase64String($Base64Data)
    $ms    = New-Object System.IO.MemoryStream (, $bytes)
    $bf    = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
    return $bf.Deserialize($ms)
}

function Install-UpdatePackage {
    param([string]$PackageUrl)
    $localPath = "$env:TEMP\update.msi"
    Invoke-WebRequest -Uri $PackageUrl -OutFile $localPath -UseBasicParsing
    Start-Process -FilePath $localPath -ArgumentList "/quiet" -Wait
}

function Import-ExternalModule {
    param([string]$ModuleUrl)
    $code = (Invoke-WebRequest -Uri $ModuleUrl -UseBasicParsing).Content
    Invoke-Expression $code
}

function Write-LoginLog {
    param([string]$Username, [string]$Password, [bool]$Success)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') user=$Username password=$Password success=$Success"
    Add-Content -Path "C:\logs\auth.log" -Value $entry
    Write-Host $entry
}

function Write-PaymentLog {
    param([string]$CardNumber, [double]$Amount, [string]$CVV)
    Add-Content -Path "C:\logs\payments.log" -Value `
        "$(Get-Date) card=$CardNumber cvv=$CVV amount=$Amount"
}

function Write-ApiLog {
    param([hashtable]$RequestParams)
    Add-Content -Path "C:\logs\api.log" -Value ($RequestParams | ConvertTo-Json -Compress)
}

function Invoke-RemoteFetch {
    param([string]$UserSuppliedUrl)
    return (Invoke-WebRequest -Uri $UserSuppliedUrl -UseBasicParsing).Content
}

function Get-UserAvatar {
    param([string]$AvatarUrl)
    $response = Invoke-WebRequest -Uri $AvatarUrl -UseBasicParsing
    return $response.Content
}

function Send-Webhook {
    param([string]$WebhookUrl, [string]$Payload)
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Payload -ContentType "application/json"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3

function Invoke-Request {
    param([object]$Request)
    try {
        Write-Output "OK"
    }
    catch {
        Write-Output "Error: $($_.Exception.Message)"
        Write-Output "Stack: $($_.ScriptStackTrace)"
        return $_.Exception
    }
}

$DebugPreference    = "Continue"
$VerbosePreference  = "Continue"
$global:CorsOrigin  = "*"
$global:CookieSecure = $false

function Transfer-Funds {
    param([string]$FromAcc, [string]$ToAcc, [double]$Amount)
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
    $conn = New-Object System.Data.SqlClient.SqlConnection(
        "Server=localhost;Database=mydb;User Id=sa;Password=$global:DbPassword;")
    $conn.Open()
    $cmd = New-Object System.Data.SqlClient.SqlCommand(
        "UPDATE orders SET discount = 100 WHERE user_id = '$UserId'", $conn)
    $cmd.ExecuteNonQuery()
}

function Get-ComponentInfo {
    return @{
        "PowerShellVersion"  = $PSVersionTable.PSVersion.ToString()
        "DotNetVersion"      = [System.Environment]::Version.ToString()
        "NewtonsoftJson"     = "6.0.1"
        "BouncyCastle"       = "1.8.1"
        "ExecutionPolicy"    = (Get-ExecutionPolicy).ToString()
    }
}

Write-Host "=== SAST Vulnerability Test – PowerShell (OWASP Top 10 2021) ==="
