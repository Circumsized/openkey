<#
.SYNOPSIS
    AutoClaw 桌面端凭据本地自动化解密脚本 (PowerShell 原生版)
.DESCRIPTION
    纯 Windows 原生实现，基于 .NET Security API 与 CryptUnprotectData，
    无需安装任何第三方环境即可一秒解出当前会话的 AutoClaw 凭据。
#>

[CmdletBinding()]
param (
    [string]$UserDataPath = [System.IO.Path]::Combine($env:APPDATA, "autoclaw")
)

# 确保执行安全路径规范化
$UserDataPath = [System.IO.Path]::GetFullPath($UserDataPath)
$LocalStatePath = [System.IO.Path]::Combine($UserDataPath, "Local State")
$AuthJsonPath = [System.IO.Path]::Combine($UserDataPath, "auth.json")

if (-not (Test-Path -LiteralPath $LocalStatePath)) {
    Write-Error "找不到 Local State 文件: $LocalStatePath"
    exit 1
}

if (-not (Test-Path -LiteralPath $AuthJsonPath)) {
    Write-Error "找不到 auth.json 文件: $AuthJsonPath"
    exit 1
}

# 1. 解析 Local State 提取 Master Key
Add-Type -AssemblyName System.Security
$localStateJson = Get-Content -LiteralPath $LocalStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
$encKeyBase64 = $localStateJson.os_crypt.encrypted_key

$keyBytesWithHeader = [Convert]::FromBase64String($encKeyBase64)
# 剥离前 5 字节 "DPAPI"
$dpapiBlob = [byte[]]::new($keyBytesWithHeader.Length - 5)
[Array]::Copy($keyBytesWithHeader, 5, $dpapiBlob, 0, $dpapiBlob.Length)

# 调用 DPAPI 解密出 32 字节 AES 密钥
$masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $dpapiBlob,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)

if ($masterKey.Length -ne 32) {
    Write-Error "解密出的 Master Key 长度异常: $($masterKey.Length) 字节 (预期 32)"
    exit 1
}

# 2. 解密 auth.json 中的 Token
$authJson = Get-Content -LiteralPath $AuthJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json

function Decrypt-Payload {
    param (
        [byte[]]$Key,
        [string]$EncryptedString
    )
    if (-not $EncryptedString.StartsWith("enc:")) {
        return $EncryptedString
    }
    $rawB64 = $EncryptedString.Substring(4)
    $rawBytes = [Convert]::FromBase64String($rawB64)
    
    if ($rawBytes.Length -lt 31) {
        throw "密文字节长度过短"
    }
    
    # 提取 IV (12 字节)
    $iv = [byte[]]::new(12)
    [Array]::Copy($rawBytes, 3, $iv, 0, 12)
    
    # 提取密文与 Tag (最后 16 字节为 Tag)
    $cipherLen = $rawBytes.Length - 15 - 16
    $ciphertext = [byte[]]::new($cipherLen)
    [Array]::Copy($rawBytes, 15, $ciphertext, 0, $cipherLen)
    
    $tag = [byte[]]::new(16)
    [Array]::Copy($rawBytes, $rawBytes.Length - 16, $tag, 0, 16)
    
    $plaintext = [byte[]]::new($cipherLen)
    
    # 使用 .NET 的 AesGcm 类
    $aesGcm = [System.Security.Cryptography.AesGcm]::new($Key)
    $aesGcm.Decrypt($iv, $ciphertext, $tag, $plaintext, $null)
    $aesGcm.Dispose()
    
    return [System.Text.Encoding]::UTF8.GetString($plaintext)
}

$accessToken = Decrypt-Payload -Key $masterKey -EncryptedString $authJson.token
$refreshToken = Decrypt-Payload -Key $masterKey -EncryptedString $authJson.refreshToken

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "AutoClaw 桌面端凭据本地自动化解密提取 (PowerShell 原生实现)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "用户编号     : $($authJson.userInfo.id)"
Write-Host "设备 ID       : $($authJson.deviceId)"
Write-Host "Access Token  : $($accessToken.Substring(0, 15))... (总长度: $($accessToken.Length))" -ForegroundColor Green
Write-Host "Refresh Token : $($refreshToken.Substring(0, 15))... (总长度: $($refreshToken.Length))" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
