# 根CA信任安装脚本 — Windows
# 用途：将PKI系统的根CA证书安装到本地计算机的受信任根存储
# 调度：新员工入职/新装机时执行一次
# 用法：.\trust_root_ca.ps1 [-PKIUrl "http://pki.internal:8080"]

param(
    [string]$PKIUrl = "http://pki.internal:8080"
)

$ErrorActionPreference = "Stop"
$caFile = "$env:TEMP\root_ca_cert.pem"

Write-Host "=== PKI根CA证书信任安装 ===" -ForegroundColor Cyan

try {
    # 下载根CA证书
    Write-Host "[1/3] 正在下载根CA证书..." -NoNewline
    Invoke-WebRequest -Uri "$PKIUrl/api/ca-certificate" -OutFile $caFile
    Write-Host " 完成" -ForegroundColor Green

    # 验证证书文件
    Write-Host "[2/3] 验证证书格式..." -NoNewline
    $content = Get-Content $caFile -Raw
    if ($content -notmatch "BEGIN CERTIFICATE") {
        Write-Host " 无效" -ForegroundColor Red
        Write-Error "下载的文件不是有效的证书格式"
        exit 1
    }
    Write-Host " 有效" -ForegroundColor Green

    # 导入到本地信任存储
    Write-Host "[3/3] 安装到受信任根存储..." -NoNewline
    Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host " 完成" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== 安装成功! ===" -ForegroundColor Cyan
    Write-Host "根CA证书已安装到本地计算机信任存储。"
    Write-Host ""
    Write-Host "浏览器访问PKI系统时不再显示安全警告。" -ForegroundColor Yellow

    # 清理临时文件
    Remove-Item $caFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host " 失败" -ForegroundColor Red
    Write-Error "安装失败: $_"
    exit 1
}
