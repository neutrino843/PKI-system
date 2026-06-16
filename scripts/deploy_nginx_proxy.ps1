# PKI系统 - Nginx反向代理部署脚本
# 用途：在Windows环境下部署Nginx + PKI反向代理
# 前置条件：Nginx已安装并添加到PATH
# 用法：.\deploy_nginx_proxy.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = "D:\PKI - 副本 (2)"
$NginxDir = "C:\nginx"
$NginxConfDir = "$NginxDir\conf"
$NginxCertDir = "$NginxDir\certs"
$NginxCrtDir = "$NginxDir\crl"

Write-Host "=== PKI Nginx反向代理部署 ===" -ForegroundColor Cyan

# 1. 检查Nginx是否安装
Write-Host "[1/5] 检查Nginx安装..." -NoNewline
if (!(Get-Command nginx -ErrorAction SilentlyContinue)) {
    Write-Host " 未安装" -ForegroundColor Yellow
    Write-Host "  请先安装Nginx: https://nginx.org/en/download.html"
    Write-Host "  或使用: choco install nginx"
    exit 1
}
Write-Host " 已安装" -ForegroundColor Green

# 2. 创建目录
Write-Host "[2/5] 创建目录结构..."
New-Item -ItemType Directory -Force -Path $NginxCertDir, $NginxCrtDir | Out-Null
Write-Host "      完成"

# 3. 复制Nginx配置
Write-Host "[3/5] 复制Nginx配置..."
$confContent = @"
worker_processes  1;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    # PKI反向代理配置
    server {
        listen 443 ssl http2;
        server_name localhost;

        ssl_certificate     $NginxCertDir\pki_server_cert.pem;
        ssl_certificate_key $NginxCertDir\pki_server_key.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;

        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
        }

        location /api/ca-certificate {
            alias $ProjectRoot\pki_demo\certs\root_ca_cert.pem;
        }
    }

    server {
        listen 80;
        server_name localhost;
        return 301 https://`$server_name`$request_uri;
    }
}
"@
Set-Content -Path "$NginxConfDir\nginx.conf" -Value $confContent
Write-Host "      完成"

# 4. 如果有PKI签发的证书，复制到Nginx目录
Write-Host "[4/5] 检查PKI证书..."
$pkiCertFiles = Get-ChildItem "$ProjectRoot\pki_demo\certs\user_*.pem" -ErrorAction SilentlyContinue
if ($pkiCertFiles.Count -gt 0) {
    Write-Host "      找到 $($pkiCertFiles.Count) 个用户证书"
} else {
    Write-Host "      暂无用户证书（请先通过PKI系统签发服务器证书）" -ForegroundColor Yellow
}

$caCertPath = "$ProjectRoot\pki_demo\certs\root_ca_cert.pem"
if (Test-Path $caCertPath) {
    Copy-Item $caCertPath "$NginxCertDir\root_ca_cert.pem" -Force
    Write-Host "      根CA证书已复制"
}

# 5. 测试并启动Nginx
Write-Host "[5/5] 启动Nginx..."
try {
    nginx -t -c "$NginxConfDir\nginx.conf"
    if ($LASTEXITCODE -eq 0) {
        nginx -c "$NginxConfDir\nginx.conf"
        Write-Host ""
        Write-Host "=== 部署成功! ===" -ForegroundColor Green
        Write-Host "PKI HTTPS服务: https://localhost/"
        Write-Host ""
        Write-Host "使用前请运行信任脚本安装根CA:" -ForegroundColor Yellow
        Write-Host "  .\scripts\trust_root_ca.ps1"
    } else {
        Write-Host "[FAIL] Nginx配置测试失败" -ForegroundColor Red
    }
} catch {
    Write-Host "[FAIL] Nginx启动失败: $_" -ForegroundColor Red
}
