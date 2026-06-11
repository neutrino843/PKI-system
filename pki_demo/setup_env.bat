@echo off
REM ============================================================
REM  PKI系统环境变量快速配置脚本
REM  用途：一键设置所有必要的环境变量
REM  修复：KEY-02 硬编码密码 → 环境变量
REM
REM  使用方式：
REM  1. 双击运行本脚本
REM  2. 按提示输入各密码
REM  3. 关闭此窗口后，运行 python main.py 即可
REM ============================================================

echo ========================================
echo   PKI系统 - 安全配置初始化
echo   请为以下密码项设置安全密码
echo ========================================
echo.
echo [提示] 密码建议至少8位，包含字母和数字
echo.

set /p CA_PWD=请输入CA私钥保护密码（默认: pki_demo_pwd）:
if "%CA_PWD%"=="" set CA_PWD=pki_demo_pwd

set /p USER_PWD=请输入用户私钥保护密码（默认: user_pwd）:
if "%USER_PWD%"=="" set USER_PWD=user_pwd

set /p P12_PWD=请输入PKCS#12导出密码（默认: p12_pwd）:
if "%P12_PWD%"=="" set P12_PWD=p12_pwd

set /p CRL_KEY=请输入CRL完整性密钥（默认: crl_hmac_key）:
if "%CRL_KEY%"=="" set CRL_KEY=crl_hmac_key

set /p AUDIT_KEY=请输入审计日志密钥（默认: audit_hmac_key）:
if "%AUDIT_KEY%"=="" set AUDIT_KEY=audit_hmac_key

REM 设置环境变量（当前会话有效）
setx PKI_CA_KEY_PASSWORD "%CA_PWD%" >nul
setx PKI_USER_KEY_PASSWORD "%USER_PWD%" >nul
setx PKI_P12_EXPORT_PASSWORD "%P12_PWD%" >nul
setx PKI_CRL_HMAC_KEY "%CRL_KEY%" >nul
setx PKI_AUDIT_HMAC_KEY "%AUDIT_KEY%" >nul

echo.
echo ========================================
echo   ✅ 环境变量设置成功！
echo   已永久保存到系统环境变量中。
echo   请关闭此窗口，重新打开命令行后生效。
echo ========================================

pause
