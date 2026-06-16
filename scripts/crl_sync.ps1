# CRL定时同步脚本 — Windows
# 用途：从PKI系统同步CRL到Nginx/IIS证书目录
# 用法：.\crl_sync.ps1 [-PKIUrl "http://localhost:8080"] [-OutputDir "C:\nginx\certs"]

param(
    [string]$PKIUrl = "http://localhost:8080",
    [string]$OutputDir = "C:\nginx\certs"
)

$ErrorActionPreference = "Stop"
$crlFile = Join-Path $OutputDir "ca_crl.pem"

# 确保输出目录存在
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

try {
    # 通过API生成CRL文件
    $response = Invoke-RestMethod -Uri "$PKIUrl/api/revoked/generate-crl" -Method Post
    $sourcePath = $response.path

    if ($sourcePath -and (Test-Path $sourcePath)) {
        Copy-Item -Path $sourcePath -Destination $crlFile -Force
        Write-Host "[OK] CRL已同步: $crlFile"
    } else {
        Write-Warning "[WARN] CRL生成路径无效: $sourcePath"
    }
} catch {
    Write-Warning "[FAIL] CRL同步失败: $_"
}

# 验证CRL文件
if (Test-Path $crlFile) {
    $content = Get-Content $crlFile -Raw
    if ($content -match "BEGIN X509 CRL|BEGIN CERTIFICATE") {
        Write-Host "[OK] CRL文件格式有效，大小: $((Get-Item $crlFile).Length) 字节"
    } else {
        Write-Warning "[WARN] CRL文件格式异常"
    }
}
