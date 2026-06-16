@echo off
chcp 65001 >nul
title PKI 系统启动器

echo ============================================
echo   PKI 系统启动器
echo ============================================

:: ============================================================
:: 重要：请在使用前配置以下环境变量
:: 将下方的占位符替换为您自己的密码/密钥值
:: 不要在生产环境中使用默认值或占位符！
:: ============================================================

:: ---------- 设置环境变量 ----------
:: 请修改等号后的值为您自己的密码/密钥
set PKI_FLASK_SECRET=YOUR_FLASK_SECRET_HERE
set PKI_CA_KEY_PASSWORD=YOUR_CA_PASSWORD_HERE
set PKI_USER_KEY_PASSWORD=YOUR_USER_PASSWORD_HERE
set PKI_CRL_HMAC_KEY=YOUR_CRL_HMAC_KEY_HERE
set PKI_AUDIT_HMAC_KEY=YOUR_AUDIT_HMAC_KEY_HERE
set PKI_P12_EXPORT_PASSWORD=YOUR_P12_EXPORT_PASSWORD_HERE

:: ---------- 请修改下方 Nginx 路径 ----------
set PKI_NGINX_DIR=C:\nginx-1.30.1

:: ---------- 1. 启动 Flask 后端 ----------
echo.
echo [1/2] 启动 Flask 后端 (端口 8080)...
start "Flask API" /MIN python api_server.py

:: 等 3 秒让 Flask 启动
timeout /t 3 /nobreak >nul

:: ---------- 2. 启动 Nginx ----------
echo [2/2] 启动 Nginx 反向代理 (端口 443)...
cd /d %PKI_NGINX_DIR%
nginx -c conf\nginx.conf 2>nul
if %errorlevel% neq 0 (
    nginx -s reload 2>nul
    echo   Nginx 已重新加载
) else (
    echo   Nginx 已启动
)

:: ---------- 3. 打开浏览器 ----------
cd /d "%~dp0"
echo.
echo ============================================
echo   🟢 启动完成！
echo.
echo   Flask:    http://localhost:8080
echo   HTTPS:    https://localhost
echo ============================================
timeout /t 2 /nobreak >nul
start https://localhost
